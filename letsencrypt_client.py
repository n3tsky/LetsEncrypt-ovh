#!/usr/bin/env python3
from binascii import unhexlify, a2b_base64
from base64 import urlsafe_b64encode
from hashlib import sha256
from OpenSSL import crypto
from OpenSSL.crypto import load_certificate_request, load_privatekey, dump_certificate_request, sign
from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1
from time import sleep
import sys
import json
from ovh_client import *
from functions import *

# Class used to communicate with Let'sEncrypt API
class LetsEncryptCORE():
    prv_key = ""
    jwk = ""
    der = ""
    domains = ""
    thumbprint = ""
    kid = ""
    URL_directory = ""
    URL_newNonce = ""
    URL_newAccount = ""
    URL_newOrder = ""
    verbose = False
    my_ovh = None

    # Constructor
    def __init__(self, url_directory, prv_key, der, jwk, domains, thumbprint, verbose):
        self.URL_directory = url_directory
        self.jwk = jwk
        self.der = der
        self.prv_key = prv_key
        self.domains = domains
        self.thumbprint = thumbprint
        self.verbose = verbose

    # Sign data (required to communicate with Let's Encrypt API)
    def sign_data(self, url, payload):
        protected = {"url": url, "alg": "RS256", "nonce": self.api_newNonce()}
        protected.update({"jwk": self.jwk} if self.kid == "" else {"kid": self.kid} )
        protected64 = c_b64(json.dumps(protected).encode("utf-8"))
        payload64 = c_b64(json.dumps(payload).encode("utf-8"))
        protected_input = ("%s.%s" % (protected64, payload64)).encode("utf-8")
        protected_input_signed = sign(self.prv_key, protected_input, "sha256")
        data = json.dumps({"protected": protected64, "payload": payload64, "signature": c_b64(protected_input_signed)})
        return data

    # Get nonce from API (required for further exchanges)
    def api_newNonce(self):
        r = HTTP_request(self.URL_newNonce)
        if "Replay-Nonce" in r.headers:
        	return r.headers["Replay-Nonce"]

    # First step - Call to Let's Encrypt API (gather all URL/API endpoints)
    def api_init(self):
        print("[*] Step 1 - Request to Let's Encrypt API")
        j_init = HTTP_load_JSON(self.URL_directory)
        self.URL_newNonce = try_and_load_JSON(j_init, "newNonce")
        self.URL_newAccount = try_and_load_JSON(j_init, "newAccount")
        self.URL_newOrder = try_and_load_JSON(j_init, "newOrder")

    # Second step - Create account
    def api_create_account(self):
        print("[*] Step 2 - Create account")
        account_payload = {"termsOfServiceAgreed": True}
        s_data = self.sign_data(self.URL_newAccount, account_payload)
        j_account = HTTP_request(self.URL_newAccount, s_data.encode("utf-8"))
        print("[*] Account already registered!" if j_account.status_code == 201 else "[*] Registered!")
        if "Location" in j_account.headers:
        	self.kid = j_account.headers["Location"]

    # Third step - Create order
    def api_create_order(self):
        print("[*] Step 3 - Create order")
        for d in self.domains:
            print("[*] Registering the following domains: %s" % d)
        order_payload = {"identifiers": [{"type": "dns", "value": d} for d in self.domains]}
        s_data = self.sign_data(self.URL_newOrder, order_payload)
        j_order = HTTP_load_JSON(self.URL_newOrder, s_data.encode("utf-8"))
        return j_order

    # Fourth step - Authorization
    def api_authorization(self, j_order):
        print("[*] Step 4 - Performing authorizations")
        auths = try_and_load_JSON(j_order, "authorizations")
        for URL_auth in auths:
            URL_finalize = try_and_load_JSON(j_order, "finalize")
            j_auth = HTTP_load_JSON(URL_auth)
            j_identifier = try_and_load_JSON(j_auth, "identifier")
            if j_identifier:
                v_domain = try_and_load_JSON(j_identifier, "value")
                print("[*] Verifying domain: %s..." % (v_domain))
                method = "dns"
                if method == "http":
                    exiting("[!] Unfortunately the HTTP method is not yet supported", 1)
                elif method == "dns":
                    challenge = [c for c in j_auth["challenges"] if c["type"] == "dns-01"][0]
                    self.my_ovh = OVHQuerier(self.verbose)
                    token = self.api_handle_DNS(challenge, v_domain)
                    # Wait for challenge to be validated by Let's Encrypt
                    self.do_loop(try_and_load_JSON(challenge, "url"), {}, "status", "valid")
                    #self.api_finalizing(try_and_load_JSON(j_order, "finalize"))

    # 4.1 - Handle challenge validation - DNS (return token value)
    def api_handle_DNS(self, challenge, domain_name):
        print("[*] Step 4.1 - Handle Let'sEncrypt challenge (DNS)")
        token = try_and_load_JSON(challenge, "token")
        keyauth = "%s.%s" % (token, self.thumbprint)
        dns_TXT_value = c_b64(sha256(keyauth.encode("utf-8")).digest())
        dns_TXT_sub = "_acme-challenge.%s." % (domain_name)
        print("[*] Update DNS record: %s TXT %s" % (dns_TXT_value, dns_TXT_sub))
        # OVH part
        info = self.my_ovh.api_domain_info(domain_name)
        self.my_ovh.display_all_domain_records(domain_name)
        new_record = self.my_ovh.api_create_TXT_record(domain_name, "_acme-challenge", dns_TXT_value)
        self.my_ovh.display_all_domain_records(domain_name)

        inc = 0 # Counter
        while True: # Check for DNS deployment
            if self.my_ovh.check_record_deployment(domain_name, "_acme-challenge", dns_TXT_value,
                info["nameServers"] if "nameServers" in info else {}):
                break
            elif inc == MAX_CHECK_DEPLOYMENT:
                self.my_ovh.api_delete_TXT_record(domain_name, new_record)
                exiting("[!] Record (challenge) was not deployed on time", 1)
            else:
                print("[!] Record not deployed yet, waiting 10 seconds...")
                sleep(10)
            inc+=1
        return dns_TXT_value

    # Fifth step - Handle challenge validation - HTTP
    def api_handle_HTTP(self):
        pass

    # Fifth step - Finalize and sign order
    def api_finalizing(self, URL_finalize):
        print("[*] Step 5 - Signing and finalizing order")
        if URL_finalize != None:
            payload = {"csr" : c_b64(self.der)}
            j_finalize = self.do_loop(URL_finalize, payload, "status", "valid")
            expiration_date = try_and_load_JSON(j_finalize, "expires")
            print("[+] Certificate is valid, expiration date is: %s" % (expiration_date))
            return j_finalize
        else:
            exiting("[!] Invalid URL while finalizing order")

    # Final step - Download certificate and write to self.path_write_cert
    def api_dl_certificate(self, URL_dl, path_write_cert):
        print("[*] Step 6 - Downloading certificate...")
        if URL_dl != None:
            r = HTTP_request(URL_dl)
            if "-----BEGIN CERTIFICATE-----" in r.text:
                print("%s..." % r.text[:150])
                write_file(path_write_cert, r.text)
                print("[+] Certificate was correctly downloaded")
            else:
            	print("[!] Invalid certificate")
        else:
            exiting("[!] Invalid URL while downloading the certificate")

    # Perform query until "value" (in key) is found
    def do_loop(self, URL, payload, key, value):
        while True:
            s_data = self.sign_data(URL, payload)
            j_data = HTTP_load_JSON(URL, s_data)
            v = try_and_load_JSON(j_data, key)
            if v != None and v == value:
                print("[+] Status is valid")
                return j_data
            print("[!] Status not valid, waiting for 2 seconds...")
            sleep(2)

# Base64 urslsafe encode
#   args: value to be encoded (str)
#   return: encoded value (str)
def c_b64(value):
    return urlsafe_b64encode(value).decode("utf-8").replace("=","")

# Load RSA key from a given file (handles TypeError and Crypto.Error)
#   args: filename
#   return: OpenSSL.crypto.PKey
def load_key_from_file(filename):
    file_content = load_file(filename)
    try:
        return load_privatekey(FILETYPE_PEM, file_content)
    except crypto.Error as e:
        print("[!] Error while loading key \"%s\" - %s" % (filename, e))
    except TypeError as e:
        print("[!] Error while loading key \"%s\" - %s" % (filename, e))
    exiting("[!] Please provide a valid RSA key file", 1)

# Load CSR (Certificate Signing Request) from a given file (handles TypeError and Crypto.Error)
#   args: filename
#   return: X509Req
def load_CSR_from_file(filename):
    file_content = load_file(filename)
    try:
        return load_certificate_request(FILETYPE_PEM, file_content)
    except crypto.Error as e:
            print("[!] Error while loading CSR \"%s\" - %s" % (filename, e))
    except TypeError as e:
        print("[!] Error while loading CSR \"%s\" - %s" % (filename, e))
    exiting("[!] Please provide a valid CSR file", 1)

# Get domains from CSR (Certificate Signing Request) file
#   args: pem (X509Req)
#   return: domains (set())
def get_domains_from_CSR(pem):
    domains = set([])
    components = dict(pem.get_subject().get_components())
    str_components = { key.decode(): val.decode() for key, val in components.items() }
    if "CN" in str_components:
        domains.add(str_components["CN"])
    return domains

# Convert a PEM CSR content to DER format
#   args: pem_content (X509Req)
#   return: str (binary)
def conv_PEMCSR_to_DER(pem_content):
    der_content = dump_certificate_request(FILETYPE_ASN1, pem_content)
    return der_content

# Create JSON web key, used to communicate through ACME protocol (handles AttributeError)
#   args: private (account) key
#   return: jwk (JSON Web Key)
def create_JSON_web_key(prv_key):
    try:
        exp = "{:06x}".format(prv_key.to_cryptography_key().private_numbers().public_numbers.e)
        modulus = "{0:x}".format(prv_key.to_cryptography_key().private_numbers().public_numbers.n)
        jwk = { "e": c_b64(unhexlify(exp)), "kty": "RSA", "n": c_b64(unhexlify(modulus)), }
        return jwk
    except AttributeError as e:
        print("[!] Error while getting exponent and modulus from private key")
        exiting("[!] Please provide a valid RSA key", 1)

# Create thumbprint for JSON Web Key
#   args: jwk (JSON Web Key)
#   return: thumbprint
def create_thumbprint(jwk):
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',',':'))
    thumbprint = c_b64(sha256(accountkey_json.encode("utf-8")).digest())
    return thumbprint

# Wrapper to create required elements which will be used to communicate with Let'sEncrypt API
#   args: private (account) key
#   return: jwk, thumbprint
def create_required_auth(prv_key):
    jwk = create_JSON_web_key(prv_key)
    thumbprint = create_thumbprint(jwk)
    return jwk, thumbprint
