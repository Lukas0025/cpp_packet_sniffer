# CPP Packet Sniffer
Project ZETA to BUT FIT IPK 2021, packet sniffer with basic filters support. Sniff packet show destion and source port/address and payload using HexDump.

## using

```sh
ipk-sniffer [-i interface_name | --interface interface_name] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
```

* list devices for sniffing
```sh
ipk-sniffer -i
```

* sniff any, but only one packet from eth0
```sh
ipk-sniffer -i eth0
#or 
ipk-sniffer -i eth0 -n 1
```

* sniff 4 icmp packets from eth0
```sh
ipk-sniffer -i eth0 --icmp -n 4
```

## example output

Exmaple sniffed TCP packet

```
2021-4-22T15:09:58+02:00 10.0.0.11 : 54620 > 140.82.113.25 : 443, length 66 bytes
  Ox0000  ce 2d e0 eb 45 6e 14 4f  8a b8 01 fa 08 00 45 00   .-..En.O......E.
  Ox0010  00 34 7a 25 40 00 40 06  b9 28 0a 00 00 0b 8c 52   .4z%@.@..(.....R
  Ox0020  71 19 d5 5c 01 bb a7 5e  84 d5 ae 93 f4 d3 80 10   q..\...^........
  Ox0030  00 25 f8 b9 00 00 01 01  08 0a b9 0f c9 48 04 92   .%...........H..
  Ox0040  48 ca                                              H.
```

* header `{time} {src_ip} : {src_port} > {dst_ip} : {dst_port}, length {packet_size} bytes`
* body (hexdump) `{offset_number} {8 BYTES as HEX} {8 BYTES as HEX} {16 BYTES decoded as ASCII}`

## build
for build program need `g++`, `make` and `pcap` library. On debian base system install using `apt install g++ make libpcap-dev`

for build exec

```sh
make
# or
make build 
```

## install

move `./ipk-sniffer` to `/usr/bin/ipk-sniffer`. Before run `install`, must run `build`

```sh
make install 
```

## uninstall

Remove `/usr/bin/ipk-sniffer` from system

```sh
make uninstall
```

## Makefile targets

* `build`       - build source code to binary file
* `debug-build` - build source code to binary file with debug informations
* `install`     - install builded file to system
* `uninstall`   - uninstall builded file from system
* `clean`       - clean repo

## Forders

* `spec`       - project specification forder
* `include`    - forder with headers files
* `src`        - forder with source codes (C++)

## files

* src/main.cpp - TOP file
* src/sniffer.cpp - Sniffer implemenation file
* include/sniffer.h - Sniffer header file
* Makefile
* README
* manual.pdf

## Documenation
 
This project is my semestral project to IPK at BUT FIT, more specific documentation you can find in documentaion file or in spec forder (CZ Only)
