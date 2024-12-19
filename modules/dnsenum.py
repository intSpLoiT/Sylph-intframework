import argparse
import socket

def enumerate_dns(target_ip, output_file=None, detailed=False, timeout=5, retry=3, reverse_lookup=False, show_raw=False):
    try:
        print(f"Enumerating DNS information for {target_ip}...")
        
        # Socket ayarları
        socket.setdefaulttimeout(timeout)
        
        # Hedef sistemin DNS ayarlarını sorgulama
        attempt = 0
        while attempt < retry:
            try:
                dns_info = socket.gethostbyaddr(target_ip)
                break
            except socket.herror:
                attempt += 1
                print(f"Retrying DNS enumeration... Attempt {attempt}/{retry}")
        else:
            print(f"Failed to enumerate DNS information for {target_ip} after {retry} attempts.")
            return
        
        # Sonuçları işleme
        result = {
            "hostname": dns_info[0],
            "aliases": dns_info[1],
            "addresses": dns_info[2]
        }
        
        if detailed:
            print("Detailed DNS Information:")
            print(f"Hostname: {dns_info[0]}")
            print(f"Aliases: {dns_info[1]}")
            print(f"Addresses: {dns_info[2]}")
        else:
            print(f"Hostname: {dns_info[0]}")
            print(f"Aliases: {dns_info[1][0] if dns_info[1] else 'None'}")
            print(f"Addresses: {dns_info[2][0] if dns_info[2] else 'None'}")
        
        # Reverse DNS lookup (isteğe bağlı)
        if reverse_lookup:
            for ip in dns_info[2]:
                try:
                    reverse_dns = socket.gethostbyaddr(ip)
                    print(f"Reverse DNS for {ip}: {reverse_dns[0]}")
                except socket.herror:
                    print(f"Reverse DNS lookup failed for {ip}")
        
        # Çıktıyı bir dosyaya kaydetme (isteğe bağlı)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(str(result))
            print(f"DNS information saved to {output_file}.")
        
        # Raw DNS bilgilerini gösterme (isteğe bağlı)
        if show_raw:
            print("\nRaw DNS Information:")
            print(dns_info)
    
    except Exception as e:
        print(f"Error enumerating DNS information for {target_ip}: {e}")

# Argparse ile komutları al
def main():
    parser = argparse.ArgumentParser(description="Enumerate DNS information for a target IP.")
    parser.add_argument('-t', '--target', required=True, help="Target IP address.")
    parser.add_argument('-o', '--output', help="Output file to save DNS information.")
    parser.add_argument('-d', '--detailed', action='store_true', help="Show detailed DNS information.")
    parser.add_argument('--timeout', type=int, default=5, help="Socket timeout in seconds (default: 5).")
    parser.add_argument('--retry', type=int, default=3, help="Number of retries on failure (default: 3).")
    parser.add_argument('--reverse_lookup', action='store_true', help="Perform reverse DNS lookup on IP addresses.")
    parser.add_argument('--show_raw', action='store_true', help="Show raw DNS information.")
    
    args = parser.parse_args()
    
    enumerate_dns(args.target, args.output, args.detailed, args.timeout, args.retry, args.reverse_lookup, args.show_raw)

if __name__ == "__main__":
    main()
