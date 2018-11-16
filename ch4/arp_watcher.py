#!/bin/env python3
# -*- coding: utf-8 -*-


from scapy.all import sniff, ARP
from signal import signal, SIGINT
import sys


def start(db_file, iface):

    ip_mac = {}

    def watch_arp(pkt):
        """executes when got arp packet from sniffer"""

        if pkt[ARP].op == 2:
            print("{} at {}".format(pkt[ARP].hwsrc, pkt[ARP].psrc))

            if not ip_mac.get(pkt[ARP].psrc):
                print("->new")
                ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc
            else:
                if ip_mac[pkt[ARP].psrc] == pkt[ARP].hwsrc:
                    print("->old")
                else:
                    print("->changed{}->{}, probably mitm or reconnect"
                          .format(ip_mac[pkt[ARP].psrc], pkt[ARP].hwsrc))

    def sig_int_handler(signum, frame):
        """manages SIGINT"""

        print("received SIGINT. saving ARP db to {}".format(db_file))
        try:
            f = open(db_file, "w")
            for (ip, mac) in ip_mac.items():
                f.write(ip + " " + mac + "\n")

            f.close()
            print("done.")
            sys.exit(0)
        except IOError:
            print("Cannot write file " + db_file)
            sys.exit(1)

    signal(SIGINT, sig_int_handler)

    try:
        fh = open(db_file, "r")
    except IOError:
        print("Cann'ot read file {}".format(db_file))
        sys.exit(1)

    for line in fh:
        line = line.rstrip()
        (ip, mac) = line.split(" ")
        ip_mac[ip] = mac

    sniff(prn=watch_arp,
          filter="arp",
          iface=iface,
          store=0)


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Usage: python scriptname.py ifname db_file")
        sys.exit(1)

    start(sys.argv[2], sys.argv[1])
