from prettytable import *
from collections import *
from scapy.all import *
from nmap import *

pcap = rdpcap('/root/Downloads/nakerah.pcap')
scanner = nmap.PortScanner()
sort_list = []
ip_list = []
x = PrettyTable()

for packets in pcap:
    if 'IP' in packets:
        ip_list.append(packets['IP'].dst)
        ip_list = list(OrderedDict.fromkeys(ip_list))

for ip in list(ip_list):
    port_scan = scanner.scan(hosts=ip, arguments='-sV -T4 -sT -p- -A')
    sort_list.append((ip, scanner[ip]['tcp'].keys().__len__()))

    for sorted_ip in sorted(sort_list, key=lambda x: x[1], reverse=True):
        print(f'Scanning IP: {ip}')
        for value in port_scan.get('scan').items():
            header = f"| Destination IP: {sorted_ip[0]} | Number of Opened Ports: {sorted_ip[1]} | OS: {value[1].get('osmatch')[0]['name']} |"
            print('-' * header.__len__())
            print(f"| Destination IP: {sorted_ip[0]} | Number of Opened Ports: {sorted_ip[1]} | OS: {value[1].get('osmatch')[0]['name']} |")
            print('-' * header.__len__())
            x.field_names = ["Port", "Service", "Product", "Version"]
            for port, port_results in value[1].get('tcp').items():
                x.add_row([port, port_results['name'], port_results['product'], port_results['version']])
print(x)
