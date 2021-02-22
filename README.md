# Agora Network Sniffer

This is a rudimentary Python3 Network Sniffer (Ethernet II, ARP, IPv4, IPv6, TCP, UDP).

![](./docs/sniffer_a4.png)

It requires L2 raw socket access (ETH_P_ALL), so **it will only work on unix-like systems** at the moment and requires **root priviliges**. I might add support for Windows at some point.

Only run this code in a network you personally own and control. This code is still work-in-progress.

## Usage

Basic usage:

```bash
sudo python3 ./agora.py
```

```bash
usage: agora.py [-h] [-v] [-l {2,3,4}] [-n] [-c] [-m {hex,char,both}] [-b BYTEWIDTH]

Agora Network Sniffer

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Print ALL header fields
  -l {2,3,4}, --layer {2,3,4}
                        Set MAXIMUM layer to parse and print (OSI). Default: 4 (Transport Layer)
  -n, --nohexdump       Do NOT print a hexdump for protocols with payload.
  -c, --nocolor         Do NOT print in color
  -m {hex,char,both}, --dumpmode {hex,char,both}
                        Hexdump: Print mode. Default: both
  -b BYTEWIDTH, --bytewidth BYTEWIDTH
                        Hexdump: number of bytes to print per line.
```

### Hexdump

The sniffer will attempt to unpack protocol layers as far as it can (or is allowed to by the `-l` parameter) and then print payloads as an `xxd`-style hexdump.

The hexdump-feature has three modes:

```bash
-m both
-m hex
-m char
```

The `both` mode is the default:
```bash
F2 9D 81 80 00 01 00 01 00 00 00 00 04 69 65 65   .............iee
65 03 6F 72 67 00 00 01 00 01 C0 0C 00 01 00 01   e.org...........                                                                                                          
00 00 05 BD 00 04 8C 62 C1 98                     .......b..
```

The `hex` mode only prints the hex field:
```bash
D5 6B 81 80 00 01 00 00 00 01 00 00 04 69 65 65 65 03 6F 72 67 00 00 1C 
00 01 C0 0C 00 06 00 01 00 00 06 5B 00 27 03 6E 73 31 C0 0C 0A 68 6F 73                                                                                                     
74 6D 61 73 74 65 72 C0 0C 77 FC 7E D1 00 00 1C 20 00 00 0E 10 00 09 3A                                                                                                     
80 00 00 0E 10
```

The `char` mode only prints the character representation:
```bash
5............ieee.org................'.ns1...hostmaster..w.~.... ......:.....
```

The default number of bytes printed per line are 16 (both), 24 (hex), 96 (char).

You can set a custom number of bytes per line with:
```bash
-b 64, --bytewidth 64
```

You can turn off the hexdump-feature completely with:

```bash
-n, --nohexdump
```

## Notes

This code was created for a tutorial on my blog [Tutorial: Build a Network Sniffer From Scratch](https://secoats.github.io/tutorial/ethernet_sniffer/).  

You can find the original code from that blog post in the git branch ["tutorial"](https://github.com/secoats/agora_sniffer/tree/tutorial).  
I might add some more features over time on the "main" branch.
