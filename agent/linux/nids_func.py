import threading
import time
import datetime
from scapy.all import sniff, DNS, DNSQR, IP

# Conf
LOG_PATH = "eagle_nids.log"
allowed_dns_ip = [i.replace('\n', '') for i in open("conf/allowed_dns_ip", "r").readlines()]
suspicious_domains = [i.replace('\n', '') for i in open("conf/suspicious_domains", "r").readlines()]

# Global
packets_list = []
date = str(datetime.datetime.now())

# --------- FONCTION DE DETECTION
def test_dns(p):
    global allowed_dns_ip
    global suspicious_domains
    
    # DNS spoofing
    if p.qr == 1 and p[IP].src not in allowed_dns_ip:
        write_alert(f"An IP address not specified in conf/allowed_dns_ip responded to a DNS query. {p[IP].src}\n")

    # DNS suspicious domains
    if p[DNSQR].qname.decode() in suspicious_domains:
        write_alert(f"A suspicious domain was requested. {p[DNSQR].qname.decode()}\n")
    
    # DNS tunneling
    if len(p[DNSQR].qname.decode()) > 30:
        write_alert(f"A domain name exceeds 30 characters. This could be DNS tunneling. {p[DNSQR].qname.decode()}\n")

    # DNS zone transfer
    if p.qd.qtype == 252: # 252 = AXFR record
        write_alert(f"Someone attempted to perform a DNS zone transfer on this machine. This attempt could be used to disclose informations or conduct a denial of service attack.\n")

# ---------

# --------- CORE
def sniffing():
    global packets_list
    while True:
        p_by_10 = sniff(iface="wlan0", count=20)
        for p in p_by_10:
            packets_list.append(p)

def analyse():
    global packets_list
    while True:
        for p in packets_list:
            if p.haslayer(DNS):
                test_dns(p)
                # Ici on rajoute les fonctions de détection pour chaque protocol testé
                packets_list.pop(0)
            else:
                print(f"{p.summary()}")
                packets_list.pop(0)
        time.sleep(1)

def write_alert(alert):
    global date
    alert = date + " : " + alert
    open(LOG_PATH, "a+").write(alert)

def main():
    recuperation_packets = threading.Thread(target=sniffing, daemon=True)
    analyse_packets = threading.Thread(target=analyse, daemon=True)

    recuperation_packets.start()
    analyse_packets.start()

    while True:
        pass

main()
