# karpsplit
Python 3 container script for ARP Spoofing and SSLSplit



## Usage
- Create your own CA certificate (good instructions are available at https://jamielinux.com/docs/openssl-certificate-authority/, follow until you've signed the server certificate )
- Change the fields <INTERMEDIATE KEY> and <INTERMEDIATE CERTIFICATE> to your new intermediate CA, and <CA CHAIN> to the chain file
- Run the program with `./karpsplit.py` (or `python3 karpsplit.py`, if python3 isn't the default version)
