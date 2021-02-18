#!/usr/bin/env python3
import struct
from network_constants import ETHER_TYPE_DICT, IP_PROTO_DICT
# U+0A75

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

    def mac_to_str(self, data):
        octets = []
        for b in data:
            octets.append(format(b, '02x'))
        return "-".join(octets)

    def __str__(self):
        ether = hex(self.ETHER_TYPE)
        trans = "UNKNOWN"

        # Translate EtherType to human readable text
        if self.ETHER_TYPE in ETHER_TYPE_DICT:
            trans = ETHER_TYPE_DICT[self.ETHER_TYPE]

        source = self.mac_to_str(self.SOURCE)
        dest = self.mac_to_str(self.DESTINATION)
        length = len(self.PAYLOAD)

        return f"[ Ethernet - {ether} {trans}; Source: {source}; Dest: {dest}; Len: {length} ]"


class IPV4:
    ID = 0x0800 # EtherType

    def __init__(self, data):
        VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, CHECKSUM, \
            SOURCE, DEST, LEFTOVER = self.unpack_ipv4(data)

        # Byte 0
        self.VERSION = VER_IHL >> 4
        self.IHL = VER_IHL & 0x0F

        # BYTE 2 & 3
        self.LENGTH = LEN

        # BYTE 9
        self.PROTOCOL = PROTO

        # BYTE 12 & 13
        self.SOURCE = SOURCE

        # BYTE 14 & 15
        self.DESTINATION = DEST

        options_len = 0
        if self.IHL > 5:
            options_len = (self.IHL - 5) * 4

        self.OPTIONS = LEFTOVER[:options_len]
        self.PAYLOAD = LEFTOVER[options_len:]

    def unpack_ipv4(self, data):
        VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, CHECKSUM, \
            SOURCE, DEST = struct.unpack("! B B H H H B B H 4s 4s", data[:20])
        
        return VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, \
            CHECKSUM, SOURCE, DEST, data[20:]

    def ipv4_to_str(self, data):
        octets = []
        for b in data:
            octets.append(format(b, 'd'))
        return ".".join(octets)

    def __str__(self):
        proto = hex(self.PROTOCOL)
        trans = "UNKNOWN"
        
        # Translate IPv4 payload Protocol to human readable name
        if self.PROTOCOL in IP_PROTO_DICT:
            trans = IP_PROTO_DICT[self.PROTOCOL]

        source = self.ipv4_to_str(self.SOURCE)
        dest = self.ipv4_to_str(self.DESTINATION)

        return f"[ IPV4 - Proto: {proto} {trans}; Source: {source}; Dest: {dest} ]"


class UDP:
    ID = 0x11 # IPv4 Protocol ID
    
    def __init__(self, data):
        SOURCE, DEST, LEN, CHKSUM, LEFTOVER = self.unpack_udp(data)
        self.SOURCE_PORT = SOURCE
        self.DEST_PORT = DEST
        self.LENGTH = LEN
        self.CHECKSUM = CHKSUM
        self.PAYLOAD = LEFTOVER

    def unpack_udp(self, data):
        SOURCE, DEST, LEN, CHKSUM = struct.unpack("! H H H H", data[:8])
        return SOURCE, DEST, LEN, CHKSUM, data[8:]

    def __str__(self):
        return f"[ UDP - Source Port: {self.SOURCE_PORT}; Destination Port: {self.DEST_PORT}; LEN: {self.LENGTH} ]"


class TCP:
    ID = 0x06 # IPv4 Protocol ID
    
    def __init__(self, data):
        SRC, DEST, SEQ, ACK_NUM, OFFSET_FLAGS, WIN_SIZE, \
            CHKSUM, URG_PTR, LEFTOVER = self.unpack_tcp(data)
        
        # Byte 0 & 1
        self.SOURCE_PORT = SRC

        # Byte 2 & 3
        self.DEST_PORT = DEST
        
        # Bytes 4, 5, 6, 7
        self.SEQUENCE_NUM = SEQ
        
        # Bytes 8, 9, 10, 11
        self.ACK_NUM = ACK_NUM
        
        # Bytes 12 & 13
        self.FLAGS = {
            "FIN" : bool( OFFSET_FLAGS & 0x01 ),
            "SYN" : bool( (OFFSET_FLAGS >> 1) & 0x01 ),
            "RST" : bool( (OFFSET_FLAGS >> 2) & 0x01 ),
            "PSH" : bool( (OFFSET_FLAGS >> 3) & 0x01 ),
            "ACK" : bool( (OFFSET_FLAGS >> 4) & 0x01 ),
            "URG" : bool( (OFFSET_FLAGS >> 5) & 0x01 ),
            "ECE" : bool( (OFFSET_FLAGS >> 6) & 0x01 ),
            "CWR" : bool( (OFFSET_FLAGS >> 7) & 0x01 ),
            "NS" :  bool( (OFFSET_FLAGS >> 8) & 0x01 )
        }

        self.OFFSET = OFFSET_FLAGS >> 12

        # Byte 14 & 15
        self.WINDOW_SIZE = WIN_SIZE
        
        # Byte 16 & 17
        self.CHECKSUM = CHKSUM

        # Byte 18 & 19
        self.URGENT_POINTER = URG_PTR

        options_len = 0
        if self.OFFSET > 5:
            options_len = (self.OFFSET - 5) * 4

        self.PARAMS = LEFTOVER[:options_len]
        self.PAYLOAD = LEFTOVER[options_len:]

    def unpack_tcp(self, data):
        SRC, DEST, SEQ, ACK_NUM, OFFSET_FLAGS, WIN_SIZE, \
            CHKSUM, URG_PTR = struct.unpack("! H H I I H H H H", data[:20])
        
        return SRC, DEST, SEQ, ACK_NUM, OFFSET_FLAGS, WIN_SIZE, \
            CHKSUM, URG_PTR, data[20:]

    def __str__(self):
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
            result += "%02X " % b

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
