#!/usr/bin/env python3
import ovh
import sys
import dns.resolver
import dns.exception
import socket
from time import sleep
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

	# Create a new DNS record (subdomain.domain) with the appropriate record value
	def api_create_TXT_record(self, domain_name, subdomain, value):
		print("[*] Add TXT domain record")
		data = {"fieldType": "TXT", "subDomain": subdomain, "target": value, "ttl": 1}
		new_record = self.api_query(API_ZONE_RECORDS % domain_name, "post", data)
		new_record_id = try_and_load_JSON(new_record, "id")
		print("[*] New DNS record: %d" % (new_record_id))
		self.api_refresh_zone(domain_name)
		return new_record_id

	# Delete a DNS record, by record ID
	def api_delete_TXT_record(self, domain_name, record_id):
		if record_id > 0:
			print("[*] Delete record ID: %d" % (record_id))
			record_to_be_deleted = list()
			record_to_be_deleted.append(self.api_fetch_domain_records_by_id(domain_name, record_id))
			self.display_records(record_to_be_deleted)
			self.api_query(API_ZONE_RECORDS_ID % (domain_name, record_id), "delete")
			self.api_refresh_zone(domain_name)
			print("[*] Record deleted!")

	# Refresh DNS zone
	def api_refresh_zone(self, domain_name):
		print("[*] Refreshing DNS zone")
		self.api_query(API_ZONE_REFRESH % domain_name, "post")
		soa = self.api_query(API_ZONE_SOA % domain_name)

	# Fetch basic info about a domain
	def api_domain_info(self, domain_name):
		info = self.api_query(API_ZONE_INFO % (domain_name))
		print("[*] Basic domain info: %s" % (info))
		return info

	# Fetch information about a record (through a record ID)
	def api_fetch_domain_records_by_id(self, domain_name, record_id):
		record_info = self.api_query(API_ZONE_RECORDS_ID % (domain_name, record_id))
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

	# Display info through tabulate
	def display_records(self, data):
		headers = ["Record ID", "Zone", "Target", "Field type", "TTL", "SubDomains"]
		print(tabulate(data, headers=headers, tablefmt="grid"))

	# Display information about all records gathered for a specific domain
	def display_all_domain_records(self, domain):
		records = self.api_fetch_domain_records(domain)
		data = self.iterate_over_domain_records(domain, records)
		if self.verbose:
			print("[*] Domain's records - %d record(s)" % (len(records)))
			self.display_records(data)

	# Check whether the record was deployed or not
	def check_record_deployment(self, domain, sub, token, nameservers={}):
		resolver = dns.resolver.Resolver()
		resolver.timeout = 3
		resolver.lifetime = 5

		# Add nameservers
		if len(nameservers) > 0:
			for n in nameservers:
				resolver.nameservers.append(socket.gethostbyname(n))
		# Try to fetch value and compare it with token
		try:
			txt_records = resolver.query("%s.%s." % (sub, domain), "TXT")
			for t in txt_records:
				if token in t.to_text():
					print("[+] Found correct token value: \"%s\"" % token)
					return True
		except dns.resolver.NXDOMAIN as e:
			print("[!] Error: %s" % e)
		return False

	# Remove all DNS records used to validate Let's Encrypt challenge(s)
	def remove_challenge_DNS_records(self, domain, sub):
		print("[*] Removing DNS records used for Let'sEncrypt challenge")
		filter = { "fieldType": "TXT", "subDomain": sub }
		records = self.api_fetch_domain_records(domain, filter)
		results = self.iterate_over_domain_records(domain, records)
		for r in results:
			if set(["TXT", sub]).issubset(r): # Even though we've used a filter
				self.api_delete_TXT_record(domain, r[0]) # r[0] is record ID
		self.api_refresh_zone(domain)

# Quick test to ensure this "client" works (OVH credentials and zone creation)
if __name__ == "__main__":
	if len(sys.argv) != 2:
		print("Usage: %s domain" % (sys.argv[0]))
		exiting("[!] Please provide a domain name", 1)

	my_ovh = OVHQuerier(True) # True => verbosity
	info = my_ovh.api_domain_info(sys.argv[1])
	my_ovh.display_all_domain_records(sys.argv[1])
	record_id = my_ovh.api_create_TXT_record(sys.argv[1], "_testing-value", "TESTING VALUE")
	my_ovh.display_all_domain_records(sys.argv[1])
	while True:
		if my_ovh.check_record_deployment(sys.argv[1], "_testing-value", "TESTING VALUE", info["nameServers"] if "nameServers" in info else {}):
			break
		else:
			print("[!] Record not deployed yet, waiting 10 seconds...")
			sleep(10)
	my_ovh.api_delete_TXT_record(sys.argv[1], record_id)
	#my_ovh.remove_challenge_DNS_records(sys.argv[1], "_testing-value")
