#!/usr/bin/env python
# importing some library to make our script easy to build
import scapy.all as scapy
import argparse

# define a function to return option
def get_options():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', dest='ip', help='IP Address / IP Range')
    option = parser.parse_args()
    return option

# define a function to do network scanning and return a list of clients
def network_scan(ip_with_range):
    arp_request_packet = scapy.ARP(pdst=ip_with_range)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combination_packet = broadcast_packet/arp_request_packet
    answered_list = scapy.srp(combination_packet, timeout=1, verbose=False)[0]
    client_list = []

    for element in answered_list:
        client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

# define a function for printing our result in the screen this result contain ip addresses and MAC addresses
def print_result(client_list):
    print('_________________________________________________________')
    print('     IP\t\t\t\t\tMAC Address')
    print('---------------------------------------------------------')

    for client in client_list:
        print('[*]  ' + client['ip'] + '\t\t\t' + client['mac'])

# call get_options() function in side a variable to get the option that returned by the previous
target = get_options()
# call network_scan() function in side a variable to get a client_list contain all the client(ip,mac)
client_list_result = network_scan(target.ip)
# call print_result() function for print our result ou the screen and that's it our script is finished
print_result(client_list_result)
# This script Made By Ismail Ben sidi khir at 5:46AM 19.05.2020