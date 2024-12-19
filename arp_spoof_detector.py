#!/usr/bin/env python
import scapy.all as scapy

def getMAC(IP):
    arp_request = scapy.ARP(pdst=IP)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP)and packet[scapy.ARP].op == 2:
        try:
            realMAC = getMAC(packet[scapy.ARP].psrc)
            responseMAC = packet[scapy.ARP].hwsrc

            if realMAC != responseMAC:
                print("[+] You are under attack!!!")
        except IndexError:
            pass

sniff("eth0")