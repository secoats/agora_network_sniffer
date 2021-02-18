#!/usr/bin/env python3
# U+0A75
# - Rudimentary Network Sniffer -
# Requires sudo/root due to raw socket access
import socket
from ethernet_tools import EthernetFrame, ARP, IPV4, UDP, TCP, hexdump
from colors import blue, yellow, green, red, violet

def main():
    ETH_P_ALL = 0x03
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

    while True:
        try:
            raw_data, addr = s.recvfrom(65565)
            
            # Ethernet
            frame = EthernetFrame(raw_data)
            print(str(frame))

            # IPV4
            if frame.ETHER_TYPE == IPV4.ID:
                ipv4 = IPV4(frame.PAYLOAD)
                print(blue("└─ " + str(ipv4)))
                    
                # UDP
                if ipv4.PROTOCOL == UDP.ID:
                    udp = UDP(ipv4.PAYLOAD)
                    print(yellow("   └─ " + str(udp)))
                    print(yellow(hexdump(udp.PAYLOAD, 5)))
                    
                # TCP
                elif ipv4.PROTOCOL == TCP.ID:
                    tcp = TCP(ipv4.PAYLOAD)
                    print(green("   └─ " + str(tcp)))
                    print(green(hexdump(tcp.PAYLOAD, 5)))

            # ARP
            elif frame.ETHER_TYPE == ARP.ID:
                arp = ARP(frame.PAYLOAD)
                print(violet("└─ " + str(arp)))
                # print(violet(arp.multi_line_summary(5)))
                print("")

        except Exception as e:
            print(red("[ Error: Failed To Parse Frame Data]"))
            print(red(str(e)))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + "Bye!")