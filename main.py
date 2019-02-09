#!/usr/bin/env python3
from argparse import ArgumentParser
import sys
from functions import *
from letsencrypt_client import *
from config import *

# Main work starts here
def do(args):
    if not (args.dns or args.http): # Ensure user chose http/dns
        print("[!] Please, provide at least one method, either --http or --dns")
        sys.exit(1)

    print()
    API_BASE_ADDRESS = LE_API_ADDRESS
    if (args.staging): # Do we use the staging (testing) environment?
        print("***** Using staging environment *****")
        API_BASE_ADDRESS = LE_STAGING_API_ADDRESS

    print("[*] Output cert. file: %s/%s" % (args.cert_path, args.cert_name))
    check_path_and_name(args.cert_path, args.cert_name)

    print("[*] Loading account key...")
    prv_key = load_key_from_file(args.account_key)
    print("[*] Done!")
    print("[*] Loading CSR - Certificate Signing Request...")
    pem = load_CSR_from_file(args.csr)
    domains = get_domains_from_CSR(pem)
    der = conv_PEMCSR_to_DER(pem)
    print("[*] Done!")
    print("[*] Creating required authentication elements...")
    jwk, thumbprint = create_required_auth(prv_key)
    print("[*] Done!")

    leCORE = LetsEncryptCORE(API_BASE_ADDRESS, prv_key, der, jwk, domains, thumbprint, args.verbose)
    leCORE.api_init()
    leCORE.api_create_account()
    j_order = leCORE.api_create_order()
    leCORE.api_authorization(j_order)
    j_finalize = leCORE.api_finalizing(try_and_load_JSON(j_order, "finalize"))
    leCORE.api_dl_certificate(try_and_load_JSON(j_finalize, "certificate"), "%s/%s" % (args.cert_path, args.cert_name))
    exiting("[+] That's all folks!", 0)

# Parse arguments
def parser():
    parser = ArgumentParser(description="Let'sEncrypt certificate handler")
    parser.add_argument("--account-key", required=True, metavar="<account.key>", help="Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, metavar="<domain.csr>", help="Certificate Signing Request")
    parser.add_argument("--cert-name", default="letsencrypt.cert", metavar="<name>", help="Name for Let's Encrypt certificate (default: \"letsencrypt.cert\")")
    parser.add_argument("--cert-path", required=True, metavar="<path>", help="Path where to write Let's Encrypt certificate (need to be writeable)")
    parser.add_argument("--contact", metavar="contact", default=None, nargs="*", help="Contact details (e.g. mailto:aaa@bbb.com) for your account-key")
    parser.add_argument("--dns", default=False, action="store_true", help="Validate challenge using DNS protocol")
    parser.add_argument("--http", default=False, action="store_true", help="Validate challenge using HTTP protocol (not working atm)")
    parser.add_argument("--staging", default=False, action="store_true", help="Use staging (testing) environment")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose output")
    args = parser.parse_args()
    return args

# Entry point
if __name__ == "__main__":
    args = parser()
    try:
        do(args)
    except KeyboardInterrupt:
        print("User requested exit...")
        sys.exit(0)
