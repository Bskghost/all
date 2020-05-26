#!/usr/bin/env  python
# MAC address changer
import subprocess
import time

print('[+] MAC Address changer Script is running...')
interfaces = ["eth0","wlan0","wlan0mon","mon0","wlan1"]
print("-------------------- INTERFACES ---------------------")

for a,b in enumerate(interfaces):
    print(f"[inter {a}] ", b)
    time.sleep(1)
print()


interface = int(input("[*] Choose interface > "))
time.sleep(1)
new_mac = input("[*] New MAC Address > ")
if interface == 0 or interface == 1 or interface == 2 or interface == 3 or interface == 4:
    print('[+] Changing MAC address for ' + interfaces[interface] + ' to ' + new_mac)

    subprocess.call(["sudo", "ifconfig", interfaces[interface], "down"])
    subprocess.call(["sudo", "ifconfig", interfaces[interface], "hw", "ether", new_mac])
    subprocess.call(["sudo", "ifconfig", interfaces[interface], "up"])
else:
    print("[!] There is an error try again...")




