from scapy.all import sniff, IP, TCP, UDP
import argparse

# Define a function to process packets
def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        if packet.haslayer(TCP):
            proto = 'TCP'
        elif packet.haslayer(UDP):
            proto = 'UDP'
        else:
            proto = 'Other'

        print(f"Source: {ip_src} -> Destination: {ip_dst} | Protocol: {proto}")
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            print(f"Payload: {bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)}")
            print()

# Define a function to detect suspicious packets
def is_suspicious(packet):
    # Example logic for detecting suspicious packets
    if IP in packet and packet[IP].proto == 6:  # Check for TCP packets
        if packet.haslayer(TCP) and (packet[TCP].flags == 0x12):  # SYN-ACK flag
            return True
    return False

# Main function to start sniffing
def main():
    parser = argparse.ArgumentParser(description="Network Traffic Monitoring Tool")
    parser.add_argument('-i', '--interface', type=str, help="Network interface to sniff on", required=True)
    args = parser.parse_args()
    
    print(f"Sniffing on interface: {args.interface}")
    sniff(iface=args.interface, prn=lambda x: process_packet(x) if not is_suspicious(x) else print(f"Suspicious Packet: {x.summary()}"))

if __name__ == "__main__":
    main()
