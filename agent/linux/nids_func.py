"""
La difficulté va être de faire en sorte que ça soit pas trop lourd comme consomation pour le système.
Je pourrais utiliser les régles de SNORT mais comme je fais ce projet pour apprendre on va crée notre propre format de regle.

Dans un premier temps
- Detecter le ssh tunneling
- Detecter les attaque DOS
- Detecter les scan NMAP
- Regle regex générique

il faut que l'analyse soit asynchrone sinon on va louper des paquets pendant l'analyse.
"""

from scapy.all import sniff

def sniffing():
    packets = sniff(iface="wlan0", count=1)
    return packets

def analyse(packets):
    packets.summary()
    return 0

def main():
    packets = sniffing()
    analyse(packets)

main()