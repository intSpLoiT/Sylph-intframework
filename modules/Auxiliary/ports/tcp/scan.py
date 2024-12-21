import socket
import multiprocessing
from datetime import datetime
from colorama import Fore, init

# Renkli çıktılar için colorama'nın başlatılması
init(autoreset=True)

# Port listesi dosyası
PORT_LIST_FILE = 'top_1000_ports.txt'

# IP adresi ve port tarama işlevi
def scan_port(ip, port):
    try:
        # Socket oluşturma
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 saniye zaman aşımı
        result = sock.connect_ex((ip, port))
        
        # Eğer bağlantı başarılıysa
        if result == 0:
            print(Fore.GREEN + f"[+] {ip} - Port {port} is OPEN")
        sock.close()
    except socket.error:
        pass  # Hata durumunda bir şey yapma

# Portları okuma ve çoklu iş parçacığı ile tarama
def scan_ports(ip):
    print(Fore.BLUE + f"[~] Starting port scan on {ip}...")
    
    with open(PORT_LIST_FILE, 'r') as file:
        ports = [int(line.strip()) for line in file.readlines()]

    # Çoklu işlemle portları taramak
    pool = multiprocessing.Pool(processes=100)  # 100 iş parçacığı kullanacağız
    pool.starmap(scan_port, [(ip, port) for port in ports])

if __name__ == "__main__":
    # Hedef IP adresi
    target_ip = "192.168.1.1"  # Hedef IP'yi burada değiştirebilirsiniz

    # Tarama başlatma
    start_time = datetime.now()
    print(Fore.BLUE + f"[~] Port scan started at {start_time}")
    scan_ports(target_ip)
    print(Fore.BLUE + f"[~] Port scan completed at {datetime.now()}")