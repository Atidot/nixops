# -*- coding: utf-8 -*-

import nixops.deployment
import os
import os.path
import sys
import threading
import fcntl
import re
import json
import copy
import hvac
import code
from uuid import uuid1 as gen_uuid

import pdb

#- api for path manipulation -#

def strip_state_paths(state,path_to_strip):
    return helper_accessor(state,path_to_strip,remove_path_prefix)

def join_state_paths(state,path_to_add):
    return helper_accessor(state,path_to_add,append_path_prefix)

def strip_depl_paths(depl,path_to_strip):
    return helper_accessor(depl,path_to_strip,remove_path_prefix)

def join_depl_paths(depl,path_to_add):
    return helper_accessor(depl,path_to_add,append_path_prefix)


#- under the hood of path manipulation -#

def remove_path_prefix(prefix,path):
    return path[len(prefix):]

def append_path_prefix(prefix,path):
    return os.path.join(prefix,path)

def helper_accessor(state,path,f):
    new_state = copy.deepcopy(state)
    deployments = new_state.get('deployments',[])
    for depl in deployments:
        nix_exprs = new_state['deployments'][depl]['attributes'].get('nixExprs',"[]")
        new_nix_exprs = []
        for expr in eval(nix_exprs):
            new_expr = f(path,expr)
            new_nix_exprs.append(new_expr)
        new_state['deployments'][depl]['attributes']['nixExprs'] = ff(unicode(repr(new_nix_exprs)))
    return new_state

def depl_helper_accessor(depl,path,f):
    new_depl = copy.deepcopy(depl)
    nix_exprs = new_depl['attributes'].get('nixExprs',"[]")
    new_nix_exprs = []
    for expr in eval(nix_exprs):
        new_expr = f(path,expr)
        new_nix_exprs.append(new_expr)
    new_depl['attributes']['nixExprs'] = ff(unicode(repr(new_nix_exprs)))
    return new_depl


#############################################################

def _subclasses(cls):
    sub = cls.__subclasses__()
    return [cls] if not sub else [g for s in sub for g in _subclasses(s)]

class TransactionalVaultFile:
    """
        Transactional access to a Vault. hides under the json logical wrapper
    """

    # Implementation notes:
    # if self.nesting > 0, then no write will propagate.
    def __init__(self):
        """Vault should be initialized and unsealed before starting to use nixops.
           after that, initialize: 
           1. VAULT_TOKEN to be the vault's root token
           2. VAULT_KEY to be the vault's unseal key
           3. VAULT_ADDR to the address of vault (if vault is initialized on the same machine, it is supposed to be set 
        """
        # we create lock in ~/nixops/locks/shared-state
        lock_dir = os.path.join(os.environ.get("HOME", ""), ".nixops/locks")
        if not os.path.exists(lock_dir): os.makedirs(lock_dir, 0700)
        lock_file_path = os.path.join(lock_dir,"shared-state")
        self._lock_file = open(lock_file_path, "w")
        fcntl.fcntl(self._lock_file, fcntl.F_SETFD, fcntl.FD_CLOEXEC) # to not keep the lock in child processes
        
        self._root_token = os.environ['VAULT_TOKEN']
        self._key = os.environ['VAULT_KEY']
        self._url = os.environ['VAULT_ADDR']
        self._nixops_base_secret = 'secret/' + os.environ["NIXOPS_SECRET_KEY"]
        print "key root",self._nixops_base_secret
        self._dir_to_strip = os.environ["NIXOPS_DIR_TO_STRIP"]

        #TODO: verify vault address before connecting?
        #TODO: this line should be wrapped with an exception and print a message that we need the enviroment variables set correctly
        vault = hvac.Client(url=os.environ['VAULT_ADDR'], token=os.environ['VAULT_TOKEN'])
            
        self._vault_cli = vault
        self.nesting = 0
        self.lock = threading.RLock()
        self._deployments = {}

#'''
#deployments are secrets, so now we hold them in a dict on memory.
#when ever we look for an uuid that is not in the dict, we will read from the vault
#and copy it into the dict. upon commit, we will remove it from the dict
#'''

    def read_depl(self,uuid):
        if uuid not in self._deployments:
            depl_key = self.read()["deployments"].get(uuid)
            if depl_key is None:
                raise Exception('deployment does not exists in vault at all!!!!!!!')
            else:
                depl = self._vault_cli.read(depl_key)
                if depl is None:
                    raise Exception("illogical state - secret value does not exist, although it's key exists in deployments")
                else:
                    self._deployments[uuid] = join_depl_paths(depl['data']['baz'],self._dir_to_strip)
        return self._deployments.get(uuid)

            
    def commit_depl(self,uuid):
        stripped_depl = strip_depl_paths(self._deployments[uuid],self._dir_to_strip)
        depl_key = self._nixops_base_secret + "/" + uuid
        self._vault_cli.write(depl_key,baz=stripped_depl,lease='1h')    
        

    def read_all_depls(self):
        for uuid in self.read()["deployments"]:
            self.read_depl(uuid)
        return self._deployments

    def set_depl(self,uuid,depl):
        self._deployments[uuid] = depl

    def set_deployments(self,deployments):
        self._deployments = deployments
        
####
    
    def read(self):
        if self.nesting == 0:
            depl = self._vault_cli.read(self._nixops_base_secret)
            return depl['data']['baz']
        else:
            assert self.nesting > 0
            return self._current_state

    # Implement Python's context  management protocol so that "with db"
    # automatically commits or rolls back.
    def __enter__(self):
        self.lock.acquire()
        if self.nesting == 0:
            fcntl.flock(self._lock_file, fcntl.LOCK_EX)
            self._ensure_db_exists()
            self.must_rollback = False
            vault_data = self._vault_cli.read(self._nixops_base_secret)['data']['baz'] #TODO: replace with read, no access to the actual data if not thru read
            self._backup_state = copy.deepcopy(vault_data)
            self._current_state = copy.deepcopy(vault_data)

        self.nesting = self.nesting + 1

    def __exit__(self, exception_type, exception_value, exception_traceback):
        if exception_type != None: self.must_rollback = True
        self.nesting = self.nesting - 1
        assert self.nesting >= 0
        if self.nesting == 0:
            if self.must_rollback:
                self._rollback()
            else:
                self._commit()
            fcntl.flock(self._lock_file, fcntl.LOCK_UN)
        self.lock.release()
    

    def _rollback(self):
        self._backup_state  = None
        self._current_state = None
        self._deployments.clear()
        pass

    def set(self, state):
        self._current_state = state

    def _commit(self):
        assert self.nesting == 0
        self._vault_cli.write(self._nixops_base_secret,baz=self._current_state,lease='1h')

        #commit also the deployments:
        for uuid in self._deployments:
            self.commit_depl(uuid)

        self._backup_state  = None
        self._current_state = None
        self._deployments.clear()
        
    def _ensure_db_exists(self):
        res = self._vault_cli.read(self._nixops_base_secret);
        if res is None:
            initial_db = {
              "schemaVersion": 0,
              "deployments": {}
            }
            self._vault_cli.write(self._nixops_base_secret,baz=initial_db,lease='1h');

    def schema_version(self): #TODO: resolve this after deciding on format for this stuffush
        state = self.read()
        version = state["schemaVersion"]
        if version is None:
            raise "illegal vault server" #TODO: proper exception
        else:
            return version

class VaultState(object):
    """NixOps state file."""

    def __init__(self):
        self.db = TransactionalVaultFile()
        self.vault_url = self.db._url
        # Check that we're not using a to new DB schema version.
        with self.db:
            version = self.db.schema_version()
            if version  > 0:
               raise Exception("this NixOps version is too old to deal with JSON schema version {0}".format(version))

    ###############################################################################################
    ## Deployment

    def query_deployments(self):
        """Return the UUIDs of all deployments in the database."""
        return self.db.read()["deployments"].keys()

    def get_all_deployments(self):
        """Return Deployment objects for every deployment in the database."""
        uuids = self.query_deployments()
        res = []
        for uuid in uuids:
            try:
                res.append(self.open_deployment(uuid=uuid))
            except nixops.deployment.UnknownBackend as e:
                sys.stderr.write("skipping deployment ‘{0}’: {1}\n".format(uuid, str(e)))
        return res

    def _find_deployment(self, uuid=None):
        all_deployments = self.db.read_all_depls()
        found = []
        if not uuid:
            found = all_deployments
        if not found:
            found = filter(lambda(id): id == uuid, all_deployments)
        if not found:
            found = filter(lambda(id): all_deployments[id]["attributes"].get("name") == uuid, all_deployments)

        if not found:
            found = filter(lambda(id): id.startswith(uuid), all_deployments)

        if not found:
            return None

        if len(found) > 1:
            if uuid:
                raise Exception("state file contains multiple deployments with the same name, so you should specify one using its UUID")
            else:
                raise Exception("state file contains multiple deployments, so you should specify which one to use using ‘-d’, or set the environment variable NIXOPS_DEPLOYMENT")
        return nixops.deployment.Deployment(self, found[0], sys.stderr)

    def open_deployment(self, uuid=None):
        """Open an existing deployment."""
        deployment = self._find_deployment(uuid=uuid)
        if deployment: return deployment
        raise Exception("could not find specified deployment in the vault at address ‘{0}’".format(self.vault_url))

    def create_deployment(self, uuid=None):
        """Create a new deployment."""
        if not uuid:
            import uuid
            uuid = str(uuid.uuid1())
        with self.db:
            state = self.db.read()
            new_empty_depl = { "attributes": {}, "resources": {} }
            state["deployments"][uuid] = self.db._nixops_base_secret + "/" + uuid
            self.db.set(state)
            self.db.set_depl(uuid,new_empty_depl)

        return nixops.deployment.Deployment(self, uuid, sys.stderr)

    def _delete_deployment(self, deployment_uuid):
        """NOTE: This is UNSAFE, it's guarded in nixops/deployment.py. Do not call this function except from there!"""
        #self.__db.execute("delete from Deployments where uuid = ?", (deployment_uuid,))
        with self.db:
            state = self.db.read()
            depl = self.db.read_depl(deployment_uuid)
            depl_key = state["deployments"].pop(deployment_uuid)
            self.db._deployments.pop(deployment_uuid, None)
            self.db._vault_cli.delete(depl_key) # deletes the deployment from the vault
            self.db.set(state)
            
            #TODO: note: this part only removes the secret from the main dataset, the deployment's secret in the vault or in the dict might still exist

    def clone_deployment(self, deployment_uuid):
        with self.db:
            if not uuid:
                import uuid
                new_uuid = str(uuid.uuid1())
            cloned_attributes = copy.deepcopy(self.db.read_depl(deployment_uuid)["attributes"])
            state["deployments"][new_uuid] = self.db._nixops_base_secret + "/" + new_uuid
 
            cloned_depl = {
                "attributes": cloned_attributes,
                "resources": {}
            }

            self.db.set(state)
            self.db.set_depl(new_uuid,cloned_depl)

        return self._find_deployment(new_uuid)

    def get_resources_for(self, deployment):
        """Get all the resources for a certain deployment"""
        resources = {}
        with self.db:
            depl = self.db.read_depl(deployment.uuid)
            state_resources = depl["resources"]
            for res_id, res in state_resources.items():
                r = self._create_state(deployment, res["type"], res["name"], res_id)
                resources[res["name"]] = r
            self.db.set_depl(deployment.uuid,depl)
        return resources

    def set_deployment_attrs(self, deployment_uuid, attrs):
        """Update deployment attributes in the state."""
        with self.db:
            depl = self.db.read_depl(deployment_uuid)
            for n, v in attrs.iteritems():
                if v == None:
                    depl["attributes"].pop(n,None)
                else:
                    depl["attributes"][n] = v
            self.db.set_depl(deployment_uuid,depl)

    def del_deployment_attr(self, deployment_uuid, attr_name):
        with self.db:
            depl = self.db.read_depl(deployment_uuid)
            depl["attributes"].pop(attr_name,None)
            self.db.set_depl(deployment_uuid,depl)

    def get_deployment_attr(self, deployment_uuid, name):
        """Get a deployment attribute from the state."""
        with self.db:
            depl = self.db.read_depl(deployment_uuid)
            result = depl["attributes"].get(name)
            if result:
                return result
            else:
                return nixops.util.undefined

    def get_all_deployment_attrs(self, deployment_uuid):
        with self.db:
            depl = self.db.read_depl(deployment_uuid)
            return copy.deepcopy(depl["attributes"])

    #TODO: i dont know if this code is relevant anymore
    def get_deployment_lock(self, deployment):
        lock_dir = os.environ.get("HOME", "") + "/.nixops/locks"
        if not os.path.exists(lock_dir): os.makedirs(lock_dir, 0700)
        lock_file_path = lock_dir + "/" + deployment.uuid
        class DeploymentLock(object):
            def __init__(self, logger, path):
                self._lock_file_path = path
                self._logger = logger
                self._lock_file = None
            def __enter__(self):
                self._lock_file = open(self._lock_file_path, "w")
                fcntl.fcntl(self._lock_file, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
                try:
                    fcntl.flock(self._lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except IOError:
                    self._logger.log(
                        "waiting for exclusive deployment lock..."
                    )
                    fcntl.flock(self._lock_file, fcntl.LOCK_EX)
            def __exit__(self, exception_type, exception_value, exception_traceback):
                if self._lock_file:
                    self._lock_file.close()
                
        return DeploymentLock(deployment.logger, lock_file_path)

    ###############################################################################################
    ## Resources

    def create_resource(self, deployment, name, type):
        with self.db:
            depl = self.db.read_depl(deployment.uuid)

            if name in depl["resources"]:
                raise Exception("resource already exists in database!")
            id = str(gen_uuid())
            depl["resources"][id] = {
                    "name": name,
                    "type" : type,
                    "attributes" : {}
            }
            #self.db.set(state)
            self.db.set_depl(deployment.uuid,depl)
            r = self._create_state(deployment, type, name, id)
            return r
        
    def delete_resource(self, deployment_uuid, res_id):
        with self.db:
            depl = self.db.read_depl(deployment_uuid)
            depl["resources"].pop(res_id)
            self.db.set_depl(deployment_uuid,depl)

    def _rename_resource(self, deployment_uuid, resource_id, new_name):
        """NOTE: Invariants are checked in nixops/deployment.py#rename"""
        with self.db:
            depl = self.db.read_depl(deployment_uuid)
            depl["resources"][resource_id]["name"] = new_name
            self.db.set_depl(deployment_uuid,depl)

    def set_resource_attrs(self, deployment_uuid, resource_id, attrs):
        with self.db:
            depl = self.db.read_depl(deployment_uuid)
            resource_attrs = depl["resources"][resource_id]["attributes"]
            for n, v in attrs.iteritems():
                if v == None:
                    resource_attrs.pop(n, None)
                else:
                    resource_attrs[n] = v
            depl["resources"][resource_id]["attributes"] = resource_attrs
            self.db.set_depl(deployment_uuid,depl)

    def del_resource_attr(self, deployment_uuid, resource_id, name):
        with self.db:
            depl = self.db.read_depl(deployment_uuid)
            resource_attrs = depl["resources"][resource_id]["attributes"]
            resource_attrs.pop(name, None)
            depl["resources"][resource_id]["attributes"] = resource_attrs
            self.db.set_depl(deployment_uuid,depl)
            
    def get_resource_attr(self, deployment_uuid, resource_id, name):
        """Get a machine attribute from the state file."""
        with self.db:
            depl = self.db.read_depl(deployment_uuid)
            resource_attrs = depl["resources"][resource_id]["attributes"]
            res = resource_attrs.get(name)
            if res != None: return res
            return nixops.util.undefined

    def get_all_resource_attrs(self, deployment_uuid, resource_id):
        with self.db:
            depl = self.db.read_depl(deployment_uuid)
            resource_attrs = depl["resources"][resource_id]["attributes"]
            return copy.deepcopy(resource_attrs)

    ### STATE
    def _create_state(self, depl, type, name, id):
        """Create a resource state object of the desired type."""

        for cls in _subclasses(nixops.resources.ResourceState):
            if type == cls.get_type():
                return cls(depl, name, id)

        raise nixops.deployment.UnknownBackend("unknown resource type ‘{0}’".format(type))
