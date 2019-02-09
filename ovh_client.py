#!/usr/bin/env python3
import ovh
import sys
import dns.resolver
import dns.exception
import socket
from tabulate import tabulate
from functions import *
from config import *

class OVHQuerier:
	client = ""
	verbose = False

	# Constructor
	def __init__(self, verbose):
		# Basic check to ensure user provided OVH creds
		if len(OVH_APP_KEY) > 0 and len(OVH_APP_SECRET) > 0 and len(OVH_CONS_KEY):
			self.client = ovh.Client(
				endpoint="ovh-eu",
				application_key=OVH_APP_KEY,
				application_secret=OVH_APP_SECRET,
				consumer_key=OVH_CONS_KEY)
			self.verbose = verbose
		else:
			exiting("[!] Please provide your OVH credentials (\"config.py\")", 1)

	# Perform calls to API (get, post and delete)
	def api_query(self, endpoint, call="get", data = {}):
		try:
			if call == "get":
				return self.client.get(endpoint, **data)
			elif call == "post":
				return self.client.post(endpoint, **data)
			elif call == "delete":
				return self.client.delete(endpoint, **data)
		except ovh.exceptions.NotCredential as e:
			exiting("[!] Error: Incorrect credentials", 1)
		except ovh.exceptions.NotGrantedCall as e:
			exiting("[!] Error: Non granted call to \"%s\"" % (endpoint), 1)
		except ovh.exceptions.BadParametersError as e:
			exiting("[!] Error: Bad parameters: %s" % (e), 1)
		except ovh.exceptions.InvalidResponse as e:
			exiting("[!] Error: Invalid response: %s" % (e), 1)
		except ovh.exceptions.ResourceNotFoundError as e:
			exiting("[!] Error: Resource not found: %s" % (e), 1)
		except ovh.exceptions.InvalidCredential as e:
			exiting("[!] Error: Invalid credential: %s" % (e), 1)

	# Fetch basic info about a domain
	def api_domain_info(self, domain_name):
		info = self.api_query(API_ZONE_INFO % (domain_name))
		print("[*] Basic domain info: %s" % (info))
		return info

	# Fetch information about a record (through a record ID)
	def api_fetch_domain_records_by_id(self, domain, record_id):
		record_info = self.api_query(API_ZONE_RECORDS_ID % (domain, record_id))
		d = list()
		for element in ["id", "zone", "target", "fieldType", "ttl", "subDomain"]:
			d.append(try_and_load_JSON(record_info, element))
		return d

	# Fetch records about a domain (can use a specific set of filters)
	def api_fetch_domain_records(self, domain, filter={}):
		return self.api_query(API_ZONE_RECORDS % domain, "get", filter)

	# Iterate (and fetch information) over domain records by record ID
	def iterate_over_domain_records(self, domain, records):
		data = list()
		for record_id in records:
			d = self.api_fetch_domain_records_by_id(domain, record_id)
			data.append(d)
		return data

	# Display information about all records gathered for a specific domain
	def display_domain_records(self, domain):
		records = self.api_fetch_domain_records(domain)
		data = self.iterate_over_domain_records(domain, records)
		headers = ["Record ID", "Zone", "Target", "Field type", "TTL", "SubDomains"]
		if self.verbose:
			print("[*] Domain's records - %d record(s)" % (len(records)))
			print(tabulate(data, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print("Usage: %s domain" % (sys.argv[0]))
		exiting("[!] Please provide a domain name", 1)

	my_ovh = OVHQuerier(True) # True => verbosity
	my_ovh.api_domain_info(sys.argv[1])
	my_ovh.display_domain_records(sys.argv[1])
