#!/usr/bin/env python3
import sys

# Exit function
#   args: exit message, exit_code
#   return: -
def exiting(message, exit_code = 0):
    print("%s\nExiting..." % (message))
    sys.exit(exit_code)

# Fetch data from JSON collection
#   args: json collection (str), value (str)
#   return: value (str) or None
def try_and_load_JSON(json, value, required=False):
    if value in json:
        return json[value]
    else:
        return None
