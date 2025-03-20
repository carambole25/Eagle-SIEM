import threading
import time
import datetime
from scapy.all import sniff, DNS, DNSQR

packets_list = []

LOG_PATH = "eagle_nids.log"

date = str(datetime.datetime.now())

# --------- FONCTION DE DETECTION
def test_dns(p):
    # for debug
    print("-----------------------")
    #print(p.show())
    print("-----------------------")
    
    # DNS tunneling
    domain_name = p[DNSQR].qname.decode()
    if len(domain_name) > 30:
        write_alert(f"A domain name exceeds 30 characters. This could be DNS tunneling. {domain_name}\n")

    # DNS zone transfer
    print(p.qd.qtype)
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
