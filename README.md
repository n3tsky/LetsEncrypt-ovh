# Let'sEncrypt OVH

Python script used to generate Let'sEncrypt certificate (without CERTBOT) through DNS challenge verification


### Features

### Installation
* Install Python3 dependencies
```
pip3 install --user -r requirements.txt
```
* Create your OVH API keys (https://api.ovh.com/createToken)
  You will need (at least) the following rights:
    - GET /domain/zone/*
    - POST /domain/zone/*
    - DELETE /domain/zone/*
    you might restrict even further: /domain/zone/{yourdomain.com}/*

* Set up your API keys in "config.py"

### Usage
```
usage: main.py [-h] --account-key <account.key> --csr <domain.csr>
               [--cert-name <name>] --cert-path <path>
               [--contact [contact [contact ...]]] [--dns] [--http]
               [--staging] [-v]

Let'sEncrypt certificate handler

optional arguments:
  -h, --help                          show this help message and exit
  --account-key <account.key>         Let's Encrypt account private key
  --csr <domain.csr>                  Certificate Signing Request
  --cert-name <name>                  Name for Let's Encrypt certificate (default: "letsencrypt.cert")
  --cert-path <path>                  Path where to write Let's Encrypt certificate (need to be writeable)
  --contact [contact [contact ...]]   Contact details (e.g. mailto:aaa@bbb.com) for your account-key
  --dns                               Validate challenge using DNS protocol
  --http                              Validate challenge using HTTP protocol (not working atm)
  --staging                           Use staging (testing) environment
  -v, --verbose                       Verbose output
```


### Thanks


### ToDo
