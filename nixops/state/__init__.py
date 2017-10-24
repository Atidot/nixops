import urlparse
import sys
import sqlite3_file
import json_file
import vault_file
import pdb

class WrongStateSchemeException(Exception):
    pass

#vault_backend = "vault"
#sqlite_backend = "sqlite"
#json_backend = "json"


def open(url):
    url = urlparse.urlparse(url)

    if url.netloc == '' and 'deployments.nixops' in url.path.split('/'): # no internet loc and checking for the deployment db name 
        return sqlite3_file.StateFile(url.path) 
    elif url.netloc == '' and url.path[-4:] == "json":
        return json_file.JsonFile(url.path)
    elif "vault" in url.netloc.split('.') or "vault" in url.path.split('.'):
        return vault_file.VaultState()

    raise WrongStateSchemeException("Unknown state scheme! vault can be connect only by suppling it's domain name")
