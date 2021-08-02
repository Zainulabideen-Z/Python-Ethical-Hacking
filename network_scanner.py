#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clinets_list = []
    for element in answered_list:
        clinets_dict = {'ip': element[1].psrc, 'MAC Address': element[1].hwsrc}
        clinets_list.append(clinets_dict)
    return clinets_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n---------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["MAC Address"])

options = get_argument()
scan_result = scan(options.target)
print_result(scan_result)

scan("10.0.2.2/24")