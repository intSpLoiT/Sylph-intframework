#!/usr/bin/env python3
import subprocess
import sys
import os
import reconf
from reconf import *

if len(sys.argv) != 3:
    print("Usage: enum_ftp.py <ip address> <port>")
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

FTPSCAN = "nmap -sV -Pn -n -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oA %s/%s_ftp %s" % (port, reconf.exampth, ip_address, ip_address)
print("[+] Executing - %s" % (FTPSCAN))
results = subprocess.check_output(FTPSCAN, shell=True).decode('utf-8')
if results != "":
    print(results)

# print("INFO: Performing password discovery on FTP against " + ip_address)
# BRUTE = "./brutepwd.py -ip %s -s ftp -H" % ip_address
# subprocess.call(BRUTE, shell=True)
