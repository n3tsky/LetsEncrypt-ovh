#!/usr/bin/env python3

# HTTP headers used to perform HTTP requests (Request)
HTTP_HEADERS = {
	"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept_language": "en-US,en;q=0.5",
	"Accept_encoding": "gzip, deflate, br",
	"Content-Type": "application/jose+json",
}

MAX_LOOP = 15

### Let'sEncrypt
# Prod env.
LE_API_ADDRESS = "https://acme-v02.api.letsencrypt.org/directory"
# Staging env.
LE_STAGING_API_ADDRESS = "https://acme-staging-v02.api.letsencrypt.org/directory"

### OVH
# Keys
OVH_APP_KEY=""
OVH_APP_SECRET=""
OVH_CONS_KEY=""
# Endpoints
API_ZONE_INFO="/domain/zone/%s/"
API_ZONE_RECORDS="/domain/zone/%s/record"
API_ZONE_RECORDS_ID="/domain/zone/%s/record/%d"
API_ZONE_REFRESH="/domain/zone/%s/refresh/"
API_ZONE_SOA="/domain/zone/%s/soa"
