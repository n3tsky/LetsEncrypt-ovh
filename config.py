#!/usr/bin/env python

# Prod env.
LE_API_ADDRESS = "https://acme-v02.api.letsencrypt.org/directory"
# Staging env.
LE_STAGING_API_ADDRESS = "https://acme-staging-v02.api.letsencrypt.org/directory"

# HTTP headers used to perform HTTP requests (Request)
HTTP_HEADERS = {
	"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept_language": "en-US,en;q=0.5",
	"Accept_encoding": "gzip, deflate, br",
	"Content-Type": "application/jose+json",
}
