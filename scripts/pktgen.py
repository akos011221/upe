#!/usr/bin/env python3
import argparse
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import Ether, ARP, IP, IPv6, TCP, UDP, ICMP, sendp

def main():
    parser = argparse.ArgumentParser(
            description="Packet Generator for UPE verification",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("--iface", required=True, help="Network interface for TX")
    parser.add_argument("--src-mac", default="aa:bb:cc:dd:ee:ff", help="Source MAC address")
    parser.add_argument("--dst-mac", default="ff:ff:ff:ff:ff:ff", help="Destination MAC address")

    subparsers = parser.add_subparsers(dest="type", required=True, help="Packet type")

    # --- ARP ---
    p_arp = subparsers.add_parser("arp", help="Generate ARP packet")
    p_arp.add_argument("--op", choices=["who-has", "is-at"], default="is-at", help="ARP Operation")
    p_arp.add_argument("--src-ip", required=True, help="Sender IP (spa)")
    p_arp.add_argument("--dst-ip", required=True, help="Target IP (tpa)")
    p_arp.add_argument("--target-mac", help="Target MAC (tha). Defaults to dst-mac for Reply, 00:00.. for Request")

    # --- IPv4 ---
    p_ip4 = subparsers.add_parser("ipv4", help="Generate IPv4 packet")
    p_ip4.add_argument("--src-ip", required=True, help="Source IP")
    p_ip4.add_argument("--dst-ip", required=True, help="Destination IP")
    p_ip4.add_argument("--ttl", type=int, default=64, help="Time To Live")
    p_ip4.add_argument("--proto", choices=["tcp", "udp", "icmp"], default="tcp", help="L4 Protocol")
    p_ip4.add_argument("--sport", type=int, default=12345, help="Source Port")
    p_ip4.add_argument("--dport", type=int, default=80, help="Destination Port")

    # --- IPv6 ---
    p_ip6 = subparsers.add_parser("ipv6", help="Generate IPv6 packet")
    p_ip6.add_argument("--src-ip", required=True, help="Source IP")
    p_ip6.add_argument("--dst-ip", required=True, help="Destination IP")
    p_ip6.add_argument("--hlim", type=int, default=64, help="Hop Limit")
    p_ip6.add_argument("--proto", choices=["tcp", "udp"], default="tcp", help="L4 Protocol")
    p_ip6.add_argument("--sport", type=int, default=12345, help="Source Port")
    p_ip6.add_argument("--dport", type=int, default=80, help="Destination Port")

    args = parser.parse_args()

    # 1. Build Ethernet Header
    eth = Ether(src=args.src_mac, dst=args.dst_mac)
    pkt = None

    # 2. Build Payload
    if args.type == "arp":
        op_val = 1 if args.op == "who-has" else 2

        # Determine Target Hardware Address (tha)
        if args.target_mac:
            tha = args.target_mac
        else:
            # Default behavior
            if op_val == 1: # Request
                tha = "00:00:00:00:00:00"
            else: # Reply
                tha = args.dst_mac

        pkt = eth / ARP(op=op_val,
                        psrc=args.src_ip,
                        hwsrc=args.src_mac,
                        pdst=args.dst_ip,
                        hwdst=tha)

    elif args.type == "ipv4":
        ip = IP(src=args.src_ip, dst=args.dst_ip, ttl=args.ttl)

        if args.proto == "tcp":
            pkt = eth / ip / TCP(sport=args.sport, dport=args.dport)
        elif args.proto == "udp":
            pkt = eth / ip / UDP(sport=args.sport, dport=args.dport)
        elif args.proto == "icmp":
            pkt = eth / ip / ICMP()

    elif args.type == "ipv6":
        ip6 = IPv6(src=args.src_ip, dst=args.dst_ip, hlim=args.hlim)

        if args.proto == "tcp":
            pkt = eth / ip6 / TCP(sport=args.sport, dport=args.dport)
        elif args.proto == "udp":
            pkt = eth / ip6 / UDP(sport=args.sport, dport=args.dport)

    # 3. Send Packet
    print(f"[*] Sending {args.type.upper()} packet on {args.iface}...")
    pkt.show()
    sendp(pkt, iface=args.iface, verbose=False)
    print("[+] Packet sent.")

if __name__ == "__main__":
    main()
