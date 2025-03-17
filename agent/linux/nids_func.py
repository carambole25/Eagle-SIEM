import threading
import time
from scapy.all import sniff

packets_list = []

def sniffing():
    global packets_list
    while True:
        p = sniff(iface="wlan0", count=1)
        p.summary()
        packets_list.append(p[0])

def analyse():
    global packets_list
    while True:
        for p in packets_list:
            print(f"Analyse du paquet: {p.summary()}")
            packets_list.pop(0)
        time.sleep(1)

def main():
    recuperation_packets = threading.Thread(target=sniffing, daemon=True)
    analyse_packets = threading.Thread(target=analyse, daemon=True)

    recuperation_packets.start()
    analyse_packets.start()

    while True:
        pass

main()
