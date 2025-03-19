import threading
import time
import datetime
from scapy.all import sniff, DNS, DNSQR

packets_list = []

LOG_PATH = "eagle_nids.log"

date = str(datetime.datetime.now())

# --------- FONCTION DE DETECTION
def test_dns(p):

    # DNS tunneling
    domain_name = p[DNSQR].qname.decode()
    if len(domain_name) > 30:
        write_alert(f"A domain name exceeds 30 characters. This could be DNS tunneling. {domain_name}\n")

# ---------

# --------- CORE
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
            if p.haslayer(DNS):
                test_dns(p)
                packets_list.pop(0)


            else:
                print(f"{p.summary()}")
                packets_list.pop(0)
        time.sleep(1)

def write_alert(alert):
    global date
    alert = date + " : " + alert
    print(alert)
    open(LOG_PATH, "a+").write(alert)

def main():
    recuperation_packets = threading.Thread(target=sniffing, daemon=True)
    analyse_packets = threading.Thread(target=analyse, daemon=True)

    recuperation_packets.start()
    analyse_packets.start()

    while True:
        pass

main()
