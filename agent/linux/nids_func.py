import threading
import time
import datetime
from scapy.all import sniff, DNS, DNSQR, IP, DHCP

# Conf
LOG_PATH = "eagle_nids.log"
allowed_dns_ip = [i.replace('\n', '') for i in open("conf/allowed_dns_ip", "r").readlines()]
suspicious_domains = [i.replace('\n', '') for i in open("conf/suspicious_domains", "r").readlines()]

# Global
packets_list = []
date = str(datetime.datetime.now())

# Global pour detections fréquence inabituel
time_before_reset = 30
## Si il y a 10 packet dhcp en 30 seconde on trigger une alert
nb_packet_dhcp = 0
nb_packet_dhcp_before_alert = 10

## Si il y a 10 port (destination) différent en seconde on trigger une alert
ports_trigger = []
nb_ports_trigger_max = 30

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

def test_dhcp(p):
    global nb_packet_dhcp
    global nb_packet_dhcp_before_alert

    nb_packet_dhcp += 1

    if nb_packet_dhcp >= nb_packet_dhcp_before_alert:
        write_alert(f"{nb_packet_dhcp} DHCP packets were received in {time_before_reset} seconds. This may be a DHCP starvation attack.\n")
        nb_packet_dhcp = 0

def test_port_scanning():
    global ports_trigger
    global nb_ports_trigger_max
    if len(ports_trigger) >= nb_ports_trigger_max:
        write_alert(f"{nb_ports_trigger_max} ports were contacted within {time_before_reset} seconds. This may be a port scan. ports: {ports_trigger}\n")
        ports_trigger = []

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
            try:
                # Actuellement on récupère aussi les ports de destination des paquets que le pc envoie
                if (p.dport) not in ports_trigger:
                    ports_trigger.append(p.dport)
                    test_port_scanning()
            except:
                pass

            if p.haslayer(DNS):
                test_dns(p)
            # Ici on rajoute les fonctions de détection pour chaque protocol testé
            elif p.haslayer(DHCP):
                test_dhcp(p)

            else:
                #print(f"{p.show()}")
                pass
            packets_list.pop(0)
        time.sleep(1)

def write_alert(alert):
    global date
    alert = date + " : " + alert
    open(LOG_PATH, "a+").write(alert)

def reset_global_for_high_frequencies_detection():
    global time_before_reset
    global nb_packet_dhcp
    # ici on rajoute toute les globals de detection de fréquence qu'on va reset tout les X secondes
    time.sleep(time_before_reset)
    nb_packet_dhcp = 0
    ports_trigger = []

def main():
    recuperation_packets = threading.Thread(target=sniffing, daemon=True)
    analyse_packets = threading.Thread(target=analyse, daemon=True)
    reset_global_for_high_frequencies_detection_thread = threading.Thread(target=reset_global_for_high_frequencies_detection, daemon=True)

    recuperation_packets.start()
    analyse_packets.start()
    reset_global_for_high_frequencies_detection_thread.start()

    while True:
        pass

main()