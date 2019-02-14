# Let'sEncrypt OVH

Python script used to generate Let'sEncrypt certificate (without CERTBOT) through DNS challenge verification

### Features
* Python3 (full pythonic instructions)
* All-in-one script (no need to update DNS zones manually)
* Let's Encrypt staging or production environment

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

#### Create a Let's Encrypt account private key
```
openssl genrsa 4096 > account.key
```

#### Create a Certificate Signing Request (CSR) for your domain(s)
```
# Generate a domain private key (if you haven't already)
openssl genrsa 4096 > domain.key
# For a single domain
openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr
```

#### Run the script and get a signed certificate
```
  ./main.py --account-key account.key --csr domain.csr --cert-path /path/to/directory --cert-name le.cert --contact mailto:aaa@bbb.com --dns
```

### Add your certificate to your configuration

* Nginx
```
server {
    listen 443 ssl;
    server_name yoursite.com, www.yoursite.com;

    ssl_certificate /path/to/signed_chain.crt;
    ssl_certificate_key /path/to/domain.key;
    ...the rest of your config
}
```
* Apache
```
<VirtualHost yoursite.com>
    ...the rest of your config
    SSLEngine on
    SSLCertificateFile /path/to/signed_chain.crt
    SSLCertificateKeyFile /path/to/domain.key
    ...the rest of your config
</VirtualHost>
```


### Auto renew

  * Step 1 - Create a dedicated (low-privileged) user
```
  root# useradd letsencrypt
```
  * Step 2 - Allow user to reload web server (e.g.: Apache)
```
  root# sudo visudo
  # Add the following line
  letsencrypt ALL=(ALL) NOPASSWD: /usr/sbin/apachectl graceful
```
  * Step 3 - As user define a cron job
```
  letsencrypt$ crontab -l
  # Run once every 3 months (90 days)
  0 0 1 */3 *  /home/letsencrypt/Documents/LetsEncrypt-ovh/main.py --account-key account.key --csr domain.csr --cert-path /path/to/directory --cert-name le.cert --contact mailto:aaa@bbb.com --dns && sudo apachectl graceful
```

* Make sure that the path to your directory is writeable
* Backup your keys
* Do not allow this script to be able to read your private keys
* Do not run this script as "root" (there is no need for that)

#### More information about usage:
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

### Thanks/Credits
* https://github.com/diafygi/acme-tiny
* https://github.com/rbeuque74/letsencrypt-ovh-hook

### ToDo
* Handle contact information
* Handle HTTP verification method
