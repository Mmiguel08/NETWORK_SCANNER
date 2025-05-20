#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_argumment():
    parser = optparse.OptionParser()
    parser.add_option("-n", "--network", dest="network", help="Network For scanning.")
    (options, argument) = parser.parse_args()
    if not options.network:
        parser.error("[-] Invalid Argumment")
    
    return options

def scan(network):
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_resquest_boraddcast = broadcast/arp_request
    answered_list = scapy.srp(arp_resquest_boraddcast, timeout=1, verbose=False)[0]
    client_list = []
    for elemnt in answered_list:
        client_dic = {'ip':elemnt[1].psrc, 'mac':elemnt[1].hwsrc}
        client_list.append(client_dic)
    return client_list

def print_result(result_list):
    print("IP \t\t\t\t\t Mac Address")
    print("--------------------------------------------------------------")
    for client in result_list:
        print(client['ip'] + '\t\t\t\t' + client['mac'])
try:
    options = get_argumment()
    scan_result = scan(options.network)
    print_result(scan_result)
except Exception as e:
    print(e)
