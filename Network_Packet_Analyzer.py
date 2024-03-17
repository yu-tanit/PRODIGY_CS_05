from scapy.layers.inet import IP, UDP, TCP
from scapy.sendrecv import sniff

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP: {src_ip}\t Destination IP: {dst_ip}\t Protocol: {protocol}")

        if TCP in packet:
            payload = packet[TCP].payload
            print("TCP Payload:", payload)

        elif UDP in packet:
            payload = packet[UDP].payload
            print("UDP Payload:", payload)

def main():
    print("Packet Sniffer started. Press Ctrl+C to stop.")

    try:
        sniff(prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("Packet Sniffer stopped.")

if __name__ == "__main__":
    main()
