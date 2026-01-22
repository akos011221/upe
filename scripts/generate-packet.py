from scapy.all import *

# Build a packet that would pass through UPE to verify IPv4 features like 
# TTL decrement and DstMac rewrite.

pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / \
        IP(src="10.128.0.1", dst="192.168.1.1", ttl=32) / \
        TCP(dport=443)

print("Sending a packet...")
sendp(pkt, iface="veth1", verbose=False)
