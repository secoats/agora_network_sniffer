#!/usr/bin/env python3
# U+0A75
import struct
from network_constants import ETHER_TYPE_DICT, IP_PROTO_DICT


def mac_to_str(data):
    octets = []
    for b in data:
        octets.append(format(b, '02x'))
    return "-".join(octets)

def ipv4_to_str(data):
    octets = []
    for b in data:
        octets.append(format(b, 'd'))
    return ".".join(octets)

"""
            - Ethernet L2 Frame -

Assuming a raw python socket (ETH_P_ALL).

You will receive a frame without the check sequence:
        6 bytes DESTINATION MAC Address
        6 bytes SOURCE MAC Address
        2 bytes Ethernet Type Identifier
        46‑1500 bytes payload

The 4 byte check sequence (CRC) that would normally be at 
the end of the frame is already stripped.

Payload padding bytes (0x00) are also removed automatically.

Payload size may vary from the standard under some circumstances.
"""
class EthernetFrame:
    def __init__(self, data):
        dest_mac, src_mac, ethertype, payload = self.unpack_ethernet_frame(data)
        self.DESTINATION = dest_mac
        self.SOURCE = src_mac
        self.ETHER_TYPE = ethertype
        self.PAYLOAD = payload
    
    def unpack_ethernet_frame(self, data):
        dest_mac, src_mac, ethertype = struct.unpack('! 6s 6s H', data[:14])
        return dest_mac, src_mac, ethertype, data[14:]

    def __repr__(self):
        ether = hex(self.ETHER_TYPE)
        trans = "UNKNOWN"

        # Translate EtherType to human readable text
        if self.ETHER_TYPE in ETHER_TYPE_DICT:
            trans = ETHER_TYPE_DICT[self.ETHER_TYPE]

        source = mac_to_str(self.SOURCE)
        dest = mac_to_str(self.DESTINATION)
        length = len(self.PAYLOAD)

        return f"[ Ethernet - {ether} {trans}; Source: {source}; Dest: {dest}; Len: {length} ]"
    
    def __str__(self):
        return repr(self)


"""
                                ARP for MAC and IPv4  
----- ---------------------------------- --------------------------------------  
Byte |             offset 0 	        |               offset 1
----- ---------------------------------- --------------------------------------
0 	 |                        Hardware type (HTYPE)
2 	 |                        Protocol type (PTYPE)
4 	 |  Hardware address length (HLEN) 	|   Protocol address length (PLEN)
6 	 |                            Operation (OPER)
8 	 |               Sender hardware address (SHA) (first 2 bytes)
10 	 |                            (next 2 bytes)
12 	 |                            (last 2 bytes)
14 	 |               Sender protocol address (SPA) (first 2 bytes)
16 	 |                            (last 2 bytes)
18 	 |               Target hardware address (THA) (first 2 bytes)
20 	 |                            (next 2 bytes)
22 	 |                            (last 2 bytes)
24 	 |               Target protocol address (TPA) (first 2 bytes)
26 	 |                            (last 2 bytes) 
----- ---------------------------------- --------------------------------------
"""
class ARP:
    ID = 0x0806 # EtherType

    def __init__(self, data):
        htype, ptype, hlen, plen, oper = struct.unpack('! H H B B H', data[:8])
        self.HTYPE = htype
        self.PTYPE = ptype
        self.HLEN = hlen
        self.PLEN = plen
        self.OPER = oper

        if( self.HLEN != 6 or self.PLEN != 4 ):
            raise Exception("Lazy ARP Implementation Error: Only supporting ARP with IPV4 and regular MAC addresses at the moment")

        sha, spa, tha, tpa = struct.unpack('! 6s 4s 6s 4s', data[8:28])
        self.SHA = sha
        self.SPA = spa
        self.THA = tha
        self.TPA = tpa

    def arp_operation_to_str(self, oper):
        if oper == 0x01:
            return "REQUEST"
        if oper == 0x02:
            return "REPLY"
        return "UNKNOWN"

    def __repr__(self):
        oper = self.arp_operation_to_str(self.OPER)
        source_ha = mac_to_str(self.SHA)
        source_pa = ipv4_to_str(self.SPA)
        target_ha = mac_to_str(self.THA)
        target_pa = ipv4_to_str(self.TPA)

        return f"[ ARP {oper} - Source HW: {source_ha}; Source IP: {source_pa} - Dest HW: {target_ha}; Dest IP: {target_pa} ]"

    def __str__(self):
        return repr(self)

    def multi_line_summary(self, intend):
        intend = int(intend)
        oper = self.arp_operation_to_str(self.OPER)
        source_ha = mac_to_str(self.SHA)
        source_pa = ipv4_to_str(self.SPA)
        target_ha = mac_to_str(self.THA)
        target_pa = ipv4_to_str(self.TPA)

        res = ""
        res += intend * " " + "SHA: " + source_ha + "\n"
        res += intend * " " + "SPA: " + source_pa + "\n"
        res += intend * " " + "THA: " + target_ha + "\n"
        res += intend * " " + "TPA: " + target_pa + "\n"
        res += intend * " " + "Operation - " + oper 
        return res


"""
                                  IPv4 
------ --------------- ------------ --------------- --------------- 
Byte  |       0       |      1     |       2       |       3       | 
Value | Version & IHL | DSCP & ECN |             LENGTH            | B B H
------ --------------- ------------ --------------- --------------- 
Byte  |       4       |      5     |       6       |       7       |
Value |         Identification     |         Flags & Offset        | H H
------ --------------- ------------ --------------- --------------- 
Byte  |       8       |      9     |      10       |       11      |
Value |  Time To Live |  Protocol  |        Header Checksum        | B B H
------ --------------- ------------ --------------- --------------- 
Byte  |      12       |     13     |      14       |       15      |
Value |                     Source IP Address                      | 4s
------ --------------- ------------ --------------- --------------- 
Byte  |      16       |     17     |      18       |       19      |
Value |                 Destination IP Address                     | 4s
------ --------------- ------------ --------------- --------------- 
                            Options
        (4 * x) bytes more are used for options if IHL > 5,
            Needs to be a multiple of 4 bytes (32 bits).
              Otherwise the body starts here directly.
------ --------------- ------------ --------------- --------------- 
Version & IHL are 4 bits each. One byte total.
DSCP is 6 bits, ECN is 2 bits. One byte total.
Flags are 3 bits, Offset is 13 bits. Two bytes total.
"""
class IPV4:
    ID = 0x0800 # EtherType

    def __init__(self, data):
        ver_ihl, dscp_ecn, leng, ident, flags_offset, ttl, proto, chksum, \
            source, destination, leftover = self.unpack_ipv4(data)

        # Byte 0
        self.VERSION = ver_ihl >> 4
        self.IHL = ver_ihl & 0x0F

        # BYTE 1 - DSCP & ECN
        self.DSCP = (dscp_ecn & 0xFC) >> 2          # 6 bits
        self.ECN = (dscp_ecn & 0x03)                # 2 bits

        # BYTE 2 & 3
        self.LENGTH = leng
        
        # BYTE 4 & 5
        self.IDENTIFICATION = ident

        # BYTE 6 & 7
        self.FLAGS = (flags_offset & 0xE000) >> 13   # 3 bits
        self.OFFSET = (flags_offset & 0x1FFF)        # 13 bits

        # BYTE 8
        self.TIME_TO_LIVE = ttl

        # BYTE 9
        self.PROTOCOL = proto

        # Byte 10 & 11
        self.CHECKSUM = chksum

        # BYTE 12 & 13
        self.SOURCE = source

        # BYTE 14 & 15
        self.DESTINATION = destination

        options_len = 0
        if self.IHL > 5:
            options_len = (self.IHL - 5) * 4

        self.OPTIONS = leftover[:options_len]
        self.PAYLOAD = leftover[options_len:]

    def unpack_ipv4(self, data):
        ver_ihl, dscp_ecn, leng, ident, flags_offset, ttl, proto, chksum, \
            source, destination = struct.unpack("! B B H H H B B H 4s 4s", data[:20])
        
        return ver_ihl, dscp_ecn, leng, ident, flags_offset, ttl, proto, \
            chksum, source, destination, data[20:]

    def __repr__(self):
        proto = hex(self.PROTOCOL)
        trans = "UNKNOWN"
        
        # Translate IPv4 payload Protocol to human readable name
        if self.PROTOCOL in IP_PROTO_DICT:
            trans = IP_PROTO_DICT[self.PROTOCOL]

        source_ip = ipv4_to_str(self.SOURCE)
        dest_ip = ipv4_to_str(self.DESTINATION)

        return f"[ IPV4 - Proto: {proto} {trans}; Source: {source_ip}; Dest: {dest_ip}; TTL: {self.TIME_TO_LIVE} ]"

    def __str__(self):
        return repr(self)

"""
                                  UDP 
------ --------------- ------------ --------------- --------------- 
Byte  |       0       |      1     |       2       |       3       |
Value |          Source Port       |       Destination Port        |
------ --------------- ------------ --------------- --------------- 
Byte  |       4       |      5     |       6       |       7       |
Value |            Length          |            Checksum           |
------ --------------- ------------ --------------- --------------- 

Checksum is optional when used with ipv4 and mandatory when used with ipv6.
The Source Port can be unused, but Destination is required.
Source Port and Checksum are all 0x00 if unused.

The length is len(header + payload), so the total UDP datagram
"""
class UDP:
    ID = 0x11 # IPv4 Protocol ID
    
    def __init__(self, data):
        source, destination, leng, chksum, leftover = self.unpack_udp(data)
        self.SOURCE_PORT = source
        self.DEST_PORT = destination
        self.LENGTH = leng
        self.CHECKSUM = chksum
        self.PAYLOAD = leftover

    def unpack_udp(self, data):
        SOURCE, DEST, LEN, CHKSUM = struct.unpack("! H H H H", data[:8])
        return SOURCE, DEST, LEN, CHKSUM, data[8:]

    def __repr__(self):
        return f"[ UDP - Source Port: {self.SOURCE_PORT}; Destination Port: {self.DEST_PORT}; LEN: {self.LENGTH} ]"

    def __str__(self):
        return repr(self)

"""
                                  TCP 
------ --------------- ------------ --------------- --------------- 
Byte  |       0       |      1     |       2       |       3       |
Value |          Source Port       |       Destination Port        | H H
------ --------------- ------------ --------------- --------------- 
Byte  |       4       |      5     |       6       |       7       |
Value |                    Sequence number                         | I
------ --------------- ------------ --------------- --------------- 
Byte  |       8       |      9     |      10       |       11      |
Value |             Acknowledgment number (if ACK set)             | I
------ --------------- ------------ --------------- --------------- 
Byte  |      12       |     13     |      14       |       15      |
Value |     Data offset & Flags    |           Window Size         | H H
------ --------------- ------------ --------------- --------------- 
Byte  |      16       |     17     |      18       |       19      |
Value |           Checksum         |  Urgent pointer (if URG set)  | H H
------ --------------- ------------ --------------- --------------- 
                                Options
    (4 * x) bytes more are used for options if data offset > 5.
                Needs to be a multiple of 4 bytes (32 bits)
                        0 - 320 bits (0 - 40 bytes)
                Otherwise the body starts here directly.
------ --------------- ------------ --------------- --------------- 

                    Closer look at Offset & Flags:
--------------------------------- -----------------------------------------------
|          Byte 12               |                     Byte 13                   |
--------------------------------- -----------------------------------------------
| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7  |  8  |  9  | 10  | 11  | 12  | 13  | 14  | 15  |
|  Data offset  | Reserved  | NS | CWR | ECE | URG | ACK | PSH | RST | SYN | FIN |
"""
class TCP:
    ID = 0x06 # IPv4 Protocol ID
    
    def __init__(self, data):
        source, destination, seq, ack_num, offset_flags, win_size, \
            chksum, urg_ptr, leftover = self.unpack_tcp(data)
        
        # Byte 0 & 1
        self.SOURCE_PORT = source

        # Byte 2 & 3
        self.DEST_PORT = destination
        
        # Bytes 4, 5, 6, 7
        self.SEQUENCE_NUM = seq
        
        # Bytes 8, 9, 10, 11
        self.ACK_NUM = ack_num
        
        # Bytes 12 & 13
        self.FLAGS = {
            "FIN" : bool( offset_flags & 0x01 ),
            "SYN" : bool( (offset_flags >> 1) & 0x01 ),
            "RST" : bool( (offset_flags >> 2) & 0x01 ),
            "PSH" : bool( (offset_flags >> 3) & 0x01 ),
            "ACK" : bool( (offset_flags >> 4) & 0x01 ),
            "URG" : bool( (offset_flags >> 5) & 0x01 ),
            "ECE" : bool( (offset_flags >> 6) & 0x01 ),
            "CWR" : bool( (offset_flags >> 7) & 0x01 ),
            "NS" :  bool( (offset_flags >> 8) & 0x01 )
        }

        self.OFFSET = offset_flags >> 12

        # Byte 14 & 15
        self.WINDOW_SIZE = win_size
        
        # Byte 16 & 17
        self.CHECKSUM = chksum

        # Byte 18 & 19
        self.URGENT_POINTER = urg_ptr

        options_len = 0
        if self.OFFSET > 5:
            options_len = (self.OFFSET - 5) * 4

        self.PARAMS = leftover[:options_len]
        self.PAYLOAD = leftover[options_len:]

    def unpack_tcp(self, data):
        SRC, DEST, SEQ, ACK_NUM, OFFSET_FLAGS, WIN_SIZE, \
            CHKSUM, URG_PTR = struct.unpack("! H H I I H H H H", data[:20])
        
        return SRC, DEST, SEQ, ACK_NUM, OFFSET_FLAGS, WIN_SIZE, \
            CHKSUM, URG_PTR, data[20:]

    def __repr__(self):
        active_flags = []

        for key in self.FLAGS:
            if self.FLAGS[key]:
                active_flags.append(key)

        flags_str = ', '.join(active_flags)
        
        res = "[ TCP - "
        res += f"Source Port: {self.SOURCE_PORT}; "
        res += f"Destination Port: {self.DEST_PORT}; "
        res += f"Flags: ({flags_str}); "
        res += f"Sequence: {self.SEQUENCE_NUM}; "
        res += f"ACK_NUM: {self.ACK_NUM} "
        res += "]"
        return res

    def __str__(self):
        return repr(self)

"""
- Hex Dump - 
Example Output:

58 07 01 00 00 01 00 00 00 00 00 00 06 67 6F 6F   X............goo
67 6C 65 03 63 6F 6D 00 00 01 00 01               gle.com.....
"""
def hexdump(bytes_input, left_padding=0, byte_width=16):
    current = 0
    end = len(bytes_input)
    result = ""

    while current < end:
        byte_slice = bytes_input[current : current + byte_width]
  
        # indentation
        result += " " * left_padding

        # hex section
        for b in byte_slice:
            result += format(b, '02X') + " "

        # filler
        for _ in range(byte_width - len(byte_slice)):
            result += " " * 3
        result += "  "

        # printable character section
        for b in byte_slice:
            if (b >= 32) and (b < 127):
                result += chr(b)
            else:
                result += "."

        result += "\n"
        current += byte_width

    return result
