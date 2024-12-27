#!/usr/bin/env python3
import subprocess
import sys
import pymssql

def execute_nmap(ip_address):
    """Run Nmap to gather MSSQL information."""
    nmap_command = (
        f"nmap -n -sV -sT -Pn -p 1433 --script=ms-sql-brute,ms-sql-config,"
        f"ms-sql-dac,ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-hasdbaccess,"
        f"ms-sql-info,ms-sql-query,ms-sql-tables,ms-sql-xp-cmdshell -oA {ip_address}_mssql {ip_address}"
    )
    print(f"[+] Executing: {nmap_command}")
    try:
        results = subprocess.check_output(nmap_command, shell=True, stderr=subprocess.STDOUT)
        print("[+] Nmap Results:\n", results.decode())
    except subprocess.CalledProcessError as e:
        print(f"[-] Nmap scan failed: {e.output.decode()}")


def mssql_enum(ip_address):
    """Attempt to connect to MSSQL server and enumerate information."""
    print("[+] Attempting MSSQL connection...")
    try:
        conn = pymssql.connect(server=ip_address, port=1433, user='sa', password='')  # Adjust credentials if necessary
        cursor = conn.cursor()
        print("[+] Connected to MSSQL server.")
        
        # Query server information
        queries = {
            "Version": "SELECT @@VERSION",
            "Databases": "SELECT name FROM sys.databases",
            "Logged-in Users": "SELECT login_name FROM sys.dm_exec_sessions"
        }

        for key, query in queries.items():
            print(f"[+] Enumerating {key}...")
            cursor.execute(query)
            results = cursor.fetchall()
            for row in results:
                print(f"    {row[0]}")
        
        conn.close()
    except pymssql.OperationalError as e:
        print(f"[-] MSSQL connection failed: {e}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 enum_mssql.py <ip address>")
        sys.exit(0)

    ip_address = sys.argv[1]

    # Step 1: Run Nmap for MSSQL-specific scans
    execute_nmap(ip_address)

    # Step 2: Attempt to connect to MSSQL and enumerate data
    mssql_enum(ip_address)


if __name__ == "__main__":
    main()
