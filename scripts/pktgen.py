import argparse
import sys
import logging
from scapy.all import (
        Ether, ARP, IP, IPv6, TCP, UDP, ICMP, sendp,
        ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import ICMPv6NDOptTgtLLAddr
except ImportError:
    class ICMPv6NDOptTgtLLAddr(ICMPv6NDOptSrcLLAddr):
        type = 2

def build_arp(args):
    op_val = 1 if args.op == "who-has" else 2
    # Determine Target Hardware Address (tha)
    if args.target_mac:
        tha = args.target_mac
    else:
        # Default behavior: Request -> 00:00.., Reply -> dst_mac
        tha = "00:00:00:00:00:00" if op_val == 1 else args.dst_mac

    return Ether(src=args.src_mac, dst=args.dst_mac) / ARP(
        op=op_val,
        psrc=args.src_ip,
        hwsrc=args.src_mac,
        pdst=args.dst_ip,
        hwdst=tha
    )

def build_ipv4(args):
    ip = IP(src=args.src_ip, dst=args.dst_ip, ttl=args.ttl)
    if args.proto == "tcp":
        return Ether(src=args.src_mac, dst=args.dst_mac) / ip / TCP(sport=args.sport, dport=args.dport)
    elif args.proto == "udp":
        return Ether(src=args.src_mac, dst=args.dst_mac) / ip / UDP(sport=args.sport, dport=args.dport)
    elif args.proto == "icmp":
        return Ether(src=args.src_mac, dst=args.dst_mac) / ip / ICMP()
    return None

def build_ipv6(args):
    ip6 = IPv6(src=args.src_ip, dst=args.dst_ip, hlim=args.hlim)
    if args.proto == "tcp":
        return Ether(src=args.src_mac, dst=args.dst_mac) / ip6 / TCP(sport=args.sport, dport=args.dport)
    elif args.proto == "udp":
        return Ether(src=args.src_mac, dst=args.dst_mac) / ip6 / UDP(sport=args.sport, dport=args.dport)
    return None

def build_ndp(args):
    # NDP packets must have Hop Limit = 255 (security measure)
    ip6 = IPv6(src=args.src_ip, dst=args.dst_ip, hlim=255)
    eth = Ether(src=args.src_mac, dst=args.dst_mac)

    if args.op == "ns":
        # Neighbor Solicitation (Type 135)
        # Includes Source Link-Layer Address (Type 1)
        return eth / ip6 / ICMPv6ND_NS(tgt=args.target_ip) / ICMPv6NDOptSrcLLAddr(lladdr=args.src_mac)
    
    elif args.op == "na":
        # Neighbor Advertisement (Type 136)
        # Includes Target Link-Layer Address (Type 2)
        # Flags: R=Router(0), S=Solicited(1), O=Override(1)
        return eth / ip6 / ICMPv6ND_NA(tgt=args.target_ip, R=0, S=1, O=1) / ICMPv6NDOptTgtLLAddr(lladdr=args.src_mac)
    
    return None

def main():
    parser = argparse.ArgumentParser(description="UPE Packet Generator", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--iface", required=True, help="Output interface")
    parser.add_argument("--src-mac", default="aa:bb:cc:dd:ee:ff", help="Source MAC")
    parser.add_argument("--dst-mac", default="ff:ff:ff:ff:ff:ff", help="Destination MAC")

    subparsers = parser.add_subparsers(dest="type", required=True)

    # ARP
    p_arp = subparsers.add_parser("arp")
    p_arp.add_argument("--op", choices=["who-has", "is-at"], default="is-at")
    p_arp.add_argument("--src-ip", required=True)
    p_arp.add_argument("--dst-ip", required=True)
    p_arp.add_argument("--target-mac")

    # IPv4
    p_ip4 = subparsers.add_parser("ipv4")
    p_ip4.add_argument("--src-ip", required=True)
    p_ip4.add_argument("--dst-ip", required=True)
    p_ip4.add_argument("--ttl", type=int, default=64)
    p_ip4.add_argument("--proto", choices=["tcp", "udp", "icmp"], default="tcp")
    p_ip4.add_argument("--sport", type=int, default=12345)
    p_ip4.add_argument("--dport", type=int, default=80)

    # IPv6
    p_ip6 = subparsers.add_parser("ipv6")
    p_ip6.add_argument("--src-ip", required=True)
    p_ip6.add_argument("--dst-ip", required=True)
    p_ip6.add_argument("--hlim", type=int, default=64)
    p_ip6.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    p_ip6.add_argument("--sport", type=int, default=12345)
    p_ip6.add_argument("--dport", type=int, default=80)

    # NDP
    p_ndp = subparsers.add_parser("ndp")
    p_ndp.add_argument("--src-ip", required=True)
    p_ndp.add_argument("--dst-ip", required=True)
    p_ndp.add_argument("--target-ip", required=True)
    p_ndp.add_argument("--op", choices=["ns", "na"], default="ns")

    args = parser.parse_args()

    pkt = None
    if args.type == "arp":
        pkt = build_arp(args)
    elif args.type == "ipv4":
        pkt = build_ipv4(args)
    elif args.type == "ipv6":
        pkt = build_ipv6(args)
    elif args.type == "ndp":
        pkt = build_ndp(args)

    if pkt:
        print(f"[*] Sending {args.type.upper()} packet on {args.iface}...")
        pkt.show()
        sendp(pkt, iface=args.iface, verbose=False)
        print("[+] Packet sent.")
    else:
        print("Error building packet.")

if __name__ == "__main__":
    main()
