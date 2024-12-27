#!/usr/bin/env python3

import argparse
import socket
import ipaddress
from ping3 import ping
import requests

# API for IP Geolocation Information
GEOLOCATION_API_URL = "https://ipinfo.io/{}/json"

def calculate_netmask(cidr):
    """Calculate netmask from CIDR"""
    mask = [0, 0, 0, 0]
    for i in range(cidr):
        mask[i // 8] += (1 << (7 - i % 8))
    return mask

def calculate_network(addr, mask):
    """Calculate network from IP address and netmask"""
    net = []
    for i in range(4):
        net.append(int(addr[i]) & mask[i])
    return net

def calculate_broadcast(net, cidr):
    """Calculate broadcast address"""
    broad = list(net)
    brange = 32 - cidr
    for i in range(brange):
        broad[3 - i // 8] += (1 << (i % 8))
    return broad

def ping_ip(ip):
    """Ping test"""
    response = ping(ip, timeout=1)
    if response:
        return f"Ping successful! Response time: {response:.4f} seconds"
    return "Ping failed."

def scan_ports(ip, ports):
    """Port scanning"""
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports

def reverse_dns(ip):
    """Reverse DNS lookup"""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except socket.herror:
        return "Reverse DNS lookup failed."

def list_subnet_ips(subnet):
    """List all IPs in a subnet"""
    return [str(ip) for ip in ipaddress.IPv4Network(subnet, strict=False)]

def get_geolocation(ip):
    """Retrieve geolocation info for an IP"""
    try:
        response = requests.get(GEOLOCATION_API_URL.format(ip), timeout=3)
        if response.status_code == 200:
            data = response.json()
            return {
                "City": data.get("city", "Unknown"),
                "Region": data.get("region", "Unknown"),
                "Country": data.get("country", "Unknown"),
                "ISP": data.get("org", "Unknown")
            }
        return "Failed to retrieve geolocation info."
    except requests.RequestException:
        return "API connection failed."

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Vortex: Subnet Calculator and Network Tools")
    parser.add_argument("ip", help="IP address (e.g., 192.168.1.1)")
    parser.add_argument("--cidr", type=int, default=32, help="CIDR value (optional, default: 32)")
    parser.add_argument("--ports", nargs="*", type=int, default=[80, 443, 22, 21, 8080],
                        help="Port numbers to scan (default: 80, 443, 22, 21, 8080)")
    args = parser.parse_args()

    addr = args.ip.split('.')
    cidr = args.cidr

    # Calculate netmask
    mask = calculate_netmask(cidr)

    # Calculate network and broadcast addresses
    net = calculate_network(addr, mask)
    broad = calculate_broadcast(net, cidr)

    # List all IPs in the subnet
    subnet = f"{args.ip}/{args.cidr}"
    ip_list = list_subnet_ips(subnet)

    # Print results
    print("Welcome to Vortex!")
    print("Here are your results:")
    print("Address: ", args.ip)
    print("Netmask: ", ".".join(map(str, mask)))
    print("Network: ", ".".join(map(str, net)))
    print("Broadcast: ", ".".join(map(str, broad)))
    print(f"Subnet ({subnet}) IPs: {', '.join(ip_list[:5])} ... (Total: {len(ip_list)})")

    # Additional features
    print("\nAdditional Features:")
    print("1. Ping Test:")
    print(ping_ip(args.ip))

    print("\n2. Port Scanning:")
    open_ports = scan_ports(args.ip, args.ports)
    print(f"Open ports: {open_ports if open_ports else 'No open ports found.'}")

    print("\n3. Reverse DNS Lookup:")
    print(reverse_dns(args.ip))

    print("\n4. Geo-Location Information:")
    geolocation = get_geolocation(args.ip)
    if isinstance(geolocation, dict):
        for key, value in geolocation.items():
            print(f"{key}: {value}")
    else:
        print(geolocation)

if __name__ == "__main__":
    main()