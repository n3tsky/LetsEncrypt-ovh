#!/usr/bin/env python3
import sys
import os
import requests
from config import *

# Exit function
#   args: exit message, exit_code
#   return: -
def exiting(message, exit_code = 0):
    print("%s\nExiting..." % (message))
    sys.exit(exit_code)

# Read data from file (handles IOError)
#   args: filename
#   return: content of file
def load_file(filename):
    try:
        with open(filename, "r") as fin:
            return fin.read()
    except IOError as e:
        print("[!] Error while loading file \"%s\" - %s" % (filename, e))
        return None

# Write data to file (override existing content)
#   args: filename, data to write
#   return: -
def write_file(filename, data):
    print("\n[+] Writing certificate to \"%s\"" % (filename))
    with open(filename, "w") as fout:
        fout.write(data)

# Perform GET and POST requests (using module requests)
#   args: URL (str), data (str) if POST
#   return: request object (todo)
def HTTP_request(URL, data=None):
    if data == None:
        #req = requests.get(URL, data=None, headers=headers)
        req = requests.get(URL, headers=HTTP_HEADERS)
    else:
        req = requests.post(URL, data=data, headers=HTTP_HEADERS)

    if req.status_code in (200, 201, 204):
        return req
    elif req.status_code in (429, 400):
        print(req.text)
    else:
        print(req.text)
        print("[!] Error code: %d" % (req.status_code))

# Perform requests and load into JSON object
#   args: URL (str), data (str) if POST
#   return: JSON object
def HTTP_load_JSON(URL, data=None):
    req_result = HTTP_request(URL, data)
    return req_result.json()

# Fetch data from JSON collection
#   args: json collection (str), value (str)
#   return: value (str) or None
def try_and_load_JSON(json, value, required=False):
    if value in json:
        return json[value]
    else:
        return None

# Determine whether a path (directory and file) is writeable
#   args: path (str) and name (str)
#   return: True if writeable, False otherwise
def check_path_and_name(directory, name):
    full_path = "%s/%s" % (directory, name)
    if os.path.exists(directory): # Does path exists?
        if os.path.isfile(full_path): # File exists
            if os.access(full_path, os.W_OK):
                print("[!] Beware - file \"%s\" will be overwritten" % (full_path))
                return True
        else: # File doesn't exist
            if os.access(directory, os.W_OK):
                return True
    exiting("[!] Please ensure to provide a valid (existing and writeable) path and name for your certificate", 1)
