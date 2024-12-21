import socket
import multiprocessing
from datetime import datetime
from colorama import Fore, init

# Renkli çıktılar için colorama'nın başlatılması
init(autoreset=True)

# Port listesi dosyası
PORT_LIST_FILE = 'top_1000_ports.txt'

# IP adresi ve port tarama işlevi (UDP için)
def scan_udp_port(ip, port):
    try:
        # UDP soketi oluşturma
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)  # 1 saniye zaman aşımı
        
        # Veriyi göndermek için portu seçiyoruz
        message = b"ping"
        sock.sendto(message, (ip, port))
        
        # Bağlantı yanıtı alırsak port açık demektir
        data, server = sock.recvfrom(1024)
        if data:
            print(Fore.GREEN + f"[+] {ip} - UDP Port {port} is OPEN")
        sock.close()
    except socket.error:
        pass  # Hata durumunda bir şey yapma

# UDP portlarını okuma ve çoklu iş parçacığı ile tarama
def scan_ports(ip):
    print(Fore.BLUE + f"[~] Starting UDP port scan on {ip}...")
    
    with open(PORT_LIST_FILE, 'r') as file:
        ports = [int(line.strip()) for line in file.readlines()]

    # Çoklu işlemle portları taramak
    pool = multiprocessing.Pool(processes=100)  # 100 iş parçacığı kullanacağız
    pool.starmap(scan_udp_port, [(ip, port) for port in ports])

if __name__ == "__main__":
    # Hedef IP adresi
    target_ip = "192.168.1.1"  # Hedef IP'yi burada değiştirebilirsiniz

    # Tarama başlatma
    start_time = datetime.now()
    print(Fore.BLUE + f"[~] UDP port scan started at {start_time}")
    scan_ports(target_ip)
    print(Fore.BLUE + f"[~] UDP port scan completed at {datetime.now()}")