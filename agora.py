#!/usr/bin/env python3
# U+0A75
# - Rudimentary Network Sniffer -
# Requires sudo/root due to raw socket access
import socket
from argparse import ArgumentParser
from inspect import isfunction
from ethernet_tools import EthernetFrame, ARP, IPV4, IPV6, IPV6_GENERIC_EXTENSION, UDP, TCP, hexdump
from colors import blue, yellow, green, red, violet, beige

banner = """
      db       .g8\"\"\"bgd    .g8\"\"8q. `7MM\"\"\"Mq.        db      
     ;MM:    .dP'     `M  .dP'    `YM. MM   `MM.      ;MM:     
    ,V^MM.   dM'       `  dM'      `MM MM   ,M9      ,V^MM.    
   ,M  `MM   MM           MM        MM MMmmdM9      ,M  `MM    
   AbmmmqMA  MM.    `7MMF'MM.      ,MP MM  YM.      AbmmmqMA   
  A'     VML `Mb.     MM  `Mb.    ,dP' MM   `Mb.   A'     VML  
.AMA.   .AMMA. `"bmmmdPY    `"bmmd"' .JMML. .JMM..AMA.   .AMMA.
"""

ETH_P_ALL = 0x03

class CONFIG:
    max_layer = 4
    verbose = False
    hexdump = True
    colorize = True
    hex_mode = True 
    char_mode = True
    byte_width = 16
    byte_width_min = 4

def color_print(text, color=None, intend=0, first=False, end="\n"):
    result = ""
    if intend > 0:
        if first:
            result += "   " * (intend - 1)
            result += "└─ "
        else:
            result += "   " * intend
    result += str(text)

    if isfunction(color) and CONFIG.colorize:
        result = color(result)

    print(result, end=end)

def hex_print(payload, color=None, intend=0):
    if not CONFIG.hexdump:
        pass

    left_padding = intend * 3
    res = hexdump(payload, left_padding=left_padding, byte_width=CONFIG.byte_width, hex_mode=CONFIG.hex_mode, char_mode=CONFIG.char_mode)
    color_print(res, color=color, end="")

def handle_ethernet2(raw_data):
    frame = EthernetFrame(raw_data)
    color_print(frame)

    # Hand over to layer 3
    if CONFIG.max_layer >= 3 and frame.ETHER_TYPE in layer3:
        layer3[frame.ETHER_TYPE](frame.PAYLOAD)

    # Hexdump payload if this is max layer
    else:
        hex_print(frame.PAYLOAD)

def handle_ipv4(frame_payload):
    ipv4 = IPV4(frame_payload)
    color_print(ipv4, color=blue, intend=1, first=True)

    # Hand over to layer 4
    if CONFIG.max_layer >= 4 and ipv4.PROTOCOL in layer4:
        layer4[ipv4.PROTOCOL](ipv4.PAYLOAD)
    
    # Hexdump payload if this is max layer
    else:
        hex_print(ipv4.PAYLOAD, color=blue, intend=1)


def handle_ipv6(frame_payload):
    ipv6 = IPV6(frame_payload)
    color_print(ipv6, color=beige, intend=1, first=True)

    # Build IPv6 extension headers if they exist
    allowed_extensions = 12
    next_header = ipv6.NEXT_HEADER
    leftover = ipv6.PAYLOAD

    while next_header in IPV6_GENERIC_EXTENSION.ID_DICT:
        ext_header = IPV6_GENERIC_EXTENSION(leftover)
        color_print(ext_header, color=beige, intend=1, first=False)

        next_header = ext_header.NEXT_HEADER
        leftover = ext_header.PAYLOAD

        # Only allow a limited number of header extensions to avoid falling pray to extension DoS
        allowed_extensions = allowed_extensions - 1
        if allowed_extensions <= 0:
            raise Exception("IPV6 extension headers exceeded maximum number of allowed extensions")

    # Hand over to layer 4
    if CONFIG.max_layer >= 4 and next_header in layer4:
        layer4[next_header](leftover)

    # Hexdump payload if this is max layer
    else:
        hex_print(leftover, color=beige, intend=1)
    

def handle_arp(frame_payload):
    arp = ARP(frame_payload)
    color_print(arp, color=violet, intend=1, first=True)

def handle_udp(datagram):
    udp = UDP(datagram)
    color_print(udp, color=yellow, intend=2, first=True)
    hex_print(udp.PAYLOAD, color=yellow, intend=2)
    
def handle_tcp(datagram):
    tcp = TCP(datagram)
    color_print(tcp, color=green, intend=2, first=True)
    hex_print(tcp.PAYLOAD, color=green, intend=2)

layer3 = {
    IPV4.ID: handle_ipv4,
    IPV6.ID: handle_ipv6,
    ARP.ID: handle_arp
}

layer4 = {
    UDP.ID: handle_udp,
    TCP.ID: handle_tcp
    #ICMP.ID: handle_icmp,
    #ICMP6.ID: handle_icmp6
}

def configure():
    parser = ArgumentParser(description='Agora Network Sniffer')
    parser.add_argument("-v", "--verbose", action="store_true", help="Print ALL header fields")
    parser.add_argument("-l", "--layer", type=int, choices=[2,3,4], default=4, help="Set MAXIMUM layer to parse and print (OSI). Default: 4 (Transport Layer)")
    parser.add_argument("-n", "--nohexdump", action="store_false", help="Do NOT print a hexdump for protocols with payload.")
    parser.add_argument("-c", "--nocolor", action="store_false", help="Do NOT print in color")
    parser.add_argument("-m", "--dumpmode", type=str, choices=["hex", "char", "both"], default="both", help="Hexdump: Print mode. Default: both")
    #parser.add_argument("-i", "--interface", type=str, help="Listening interface. If omitted default will be determined and used.")
    parser.add_argument("-b", "--bytewidth", type=int, help="Hexdump: number of bytes to print per line.")
    #parser.add_argument("-f", "--find", type=str, help="Hexdump: only print hexdumps containing a given word")
    #parser.add_argument("-w", "--wordlist", type=str, help="Hexdump: only print hexdumps containing a given word from a wordlist (Possibly expensive!)")
    #parser.add_argument("-t", "--text", type=str, help="Pretty print payload (instead of hexdump). Default encoding is utf-8. Non-utf8 chars will be escaped.")
    #parser.add_argument("-p", "--profile", type=str, help="Profile hosts in the Local Area Network")
    #parser.add_argument("-s", "--save", type=str, help="Save interesting data to file")
    args = parser.parse_args()
    
    CONFIG.max_layer = int(args.layer)
    CONFIG.verbose = bool(args.verbose)
    CONFIG.hexdump = bool(args.nohexdump)
    CONFIG.colorize = bool(args.nocolor)

    if args.dumpmode:
        CONFIG.hex_mode = bool(args.dumpmode == "hex" or args.dumpmode == "both")
        CONFIG.char_mode = bool(args.dumpmode == "char" or args.dumpmode == "both")

    if args.bytewidth and int(args.bytewidth) > CONFIG.byte_width_min:
        CONFIG.byte_width = int(args.bytewidth)
    
    elif args.dumpmode == "hex":
        CONFIG.byte_width = 24
    
    elif args.dumpmode == "char":
        CONFIG.byte_width = 96

def main():
    configure()
    color_print(banner, color=blue)
    
    if CONFIG.verbose:
        print("[*] Set verbose:", str(CONFIG.verbose))
        print("[*] Set max layer to:", CONFIG.max_layer)
        print("[*] Hexdump:", CONFIG.hexdump)
        print("[*] Hexdump byte width:", CONFIG.byte_width)
        print("[*] Colors:", CONFIG.colorize)

    print("[*] Listening...\n")

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

    while True:
        try:
            raw_data, addr = s.recvfrom(65565)
            handle_ethernet2(raw_data)

            if CONFIG.max_layer > 2:
                print()

        except Exception as e:
            color_print("[ Error: Failed To Parse Frame Data]", color=red)
            color_print(e, color=red)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + "Bye!")