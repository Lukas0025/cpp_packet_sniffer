/**
 * Project: packet sniffer - IPK variant ZETA
 * sniffer TOP file CPP
 * @author Lukáš Plevač <xpleva07> (BUT FIT)
 * @date 19.4.2021
 */

#include "sniffer.h"
#include <stdexcept>

std::vector<std::string> sniffer::devices() {
    std::vector<std::string> devs_vector;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        throw std::runtime_error(errbuf);
    }

    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        auto interface = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
        
        if (interface == NULL) {
            continue;
        }
        
        if (pcap_datalink(interface) != DLT_EN10MB) {
            continue;
        }

        devs_vector.push_back(dev->name);
    }
    
    pcap_freealldevs(alldevs);

    return devs_vector;
}

sniffer::sniffer(std::string name) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_lookupnet(name.c_str(), &this->net, &this->mask, errbuf) == -1) {
        this->net = 0;
        this->mask = 0;
    }

    this->interface = pcap_open_live(name.c_str(), BUFSIZ, 1, 1000, errbuf);
	
    if (this->interface == NULL) {
		throw std::runtime_error(errbuf);
	}

    if (pcap_datalink(this->interface) != DLT_EN10MB) {
		throw std::runtime_error("Device doesn't provide Ethernet headers");
	}
}

l3_packet sniffer::l3_decode(l1_packet packet) {
    l3_packet decode;

    //load packet as ETHERNET (L2)
    decode.ether_hdr = (struct ether_header*) packet.body;

    //load next protocol in packet
    if (ntohs(decode.ether_hdr->ether_type) == ETHERTYPE_IP) { //IPv4
        //IP header is after ETHERNET
        decode.ipv4_hdr = (struct ip*)(packet.body + sizeof(struct ether_header));
        decode.ipv4     = true;
        decode.body     = packet.body + sizeof(struct ether_header) + sizeof(struct ip);
        decode.body_len = packet.header.len - (sizeof(struct ether_header) + sizeof(struct ip));
    } else if (ntohs(decode.ether_hdr->ether_type) == ETHERTYPE_IPV6) { //IPv6
        //IP header is after ETHERNET
        decode.ipv6_hdr = (struct ip6_hdr*)(packet.body + sizeof(struct ether_header));
        decode.ipv6     = true;
        decode.body     = packet.body + sizeof(struct ether_header) + sizeof(struct ip6_hdr);
        decode.body_len = packet.header.len - (sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    } else if (ntohs(decode.ether_hdr->ether_type) == ETHERTYPE_ARP) { //ARP
        decode.arp_hdr = (struct arp_header *)(packet.body + sizeof(struct ether_header));
        decode.arp     = true;
    }
    
    return decode;
}

int sniffer::get_protocol(l3_packet packet) {
    if (packet.ipv4) {
        return packet.ipv4_hdr->ip_p;
    } else if (packet.ipv6) {
        if (packet.ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt)
        return packet.ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    } else if (packet.arp) {
        return ARP_PROT;
    }

    return UNDEF_PROT;
}


l4_packet sniffer::l4_decode(l3_packet packet) {
    l4_packet decode;
    int protocol = this->get_protocol(packet);

    if (protocol == IPPROTO_TCP) {
        decode.tcp_hdr  = (tcphdr*)packet.body;
        decode.tcp      = true;
        decode.body     = packet.body + sizeof(struct tcphdr);
        decode.body_len = packet.body_len - sizeof(struct tcphdr);
    } else if (protocol == IPPROTO_UDP) {
        decode.udp_hdr  = (udphdr*)packet.body;
        decode.udp      = true;
        decode.body     = packet.body + sizeof(struct udphdr);
        decode.body_len = packet.body_len - sizeof(struct udphdr);
    } else if (protocol == IPPROTO_ICMPV6 || protocol == IPPROTO_ICMP) {
        decode.icmp     = true;
    }

    return decode;
}


uint16_t sniffer::get_dst_port(l4_packet packet) {
    if (packet.tcp) {
        return ntohs(packet.tcp_hdr->th_dport);
    } else if (packet.udp) {
        return ntohs(packet.udp_hdr->uh_dport);
    }

    return 0;
}

uint16_t sniffer::get_src_port(l4_packet packet) {
    if (packet.tcp) {
        return ntohs(packet.tcp_hdr->th_sport);
    } else if (packet.udp) {
        return ntohs(packet.udp_hdr->uh_sport);
    }

    return 0;
}

std::string sniffer::get_src(l3_packet packet) {
    std::string addr;

    if (packet.ipv4) {
        char tmp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(packet.ipv4_hdr->ip_src), tmp, INET_ADDRSTRLEN);
        addr = tmp;
    } else if (packet.ipv6) {
        char tmp[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(packet.ipv6_hdr->ip6_src), tmp, INET6_ADDRSTRLEN);
        addr = tmp;
    } else if (packet.arp) {
        char tmp[MAC_ADDR_STRLEN];
        sprintf(
            tmp,
            "%02X:%02X:%02X:%02X:%02X:%02X",
            packet.ether_hdr->ether_shost[0],
            packet.ether_hdr->ether_shost[1],
            packet.ether_hdr->ether_shost[2],
            packet.ether_hdr->ether_shost[3],
            packet.ether_hdr->ether_shost[4],
            packet.ether_hdr->ether_shost[5]
        );  
        addr = tmp;
    }

    return addr;
}

std::string sniffer::get_dst(l3_packet packet) {
    std::string addr;

    if (packet.ipv4) {
        char tmp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(packet.ipv4_hdr->ip_dst), tmp, INET_ADDRSTRLEN);
        addr = tmp;
    } else if (packet.ipv6) {
        char tmp[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(packet.ipv6_hdr->ip6_dst), tmp, INET6_ADDRSTRLEN);
        addr = tmp;
    } else if (packet.arp) {
        char tmp[MAC_ADDR_STRLEN];
        sprintf(
            tmp,
            "%02X:%02X:%02X:%02X:%02X:%02X",
            packet.ether_hdr->ether_dhost[0],
            packet.ether_hdr->ether_dhost[1],
            packet.ether_hdr->ether_dhost[2],
            packet.ether_hdr->ether_dhost[3],
            packet.ether_hdr->ether_dhost[4],
            packet.ether_hdr->ether_dhost[5]
        );  
        addr = tmp;
    }

    return addr;
}

void sniffer::set_filter(std::string filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;		/* compilled filter */
	
    if (pcap_compile(this->interface, &fp, filter.c_str(), 0, this->net) == -1) {
		throw std::runtime_error("Couldn't parse filter");
	}
	
    if (pcap_setfilter(this->interface, &fp) == -1) {
		throw std::runtime_error(pcap_geterr(this->interface));
	}
}

void sniffer::hex_dump(const u_char* bytes, const int len) {
    
    unsigned char ascii[17]; //ascii decoded version

    int i;
    for (i = 0; i < len; i++) {

        // 16 bytes per line
        if (i % 16 == 0) {

            if (i != 0)
                printf("   %s\n", ascii); //print ASCII decoded in end of line

            //print line/byte number
            printf("  Ox%04x ", i); 
        }

        printf(" %02x", bytes[i]);

        //print space in center
        if (i % 16 == 7) {
            printf(" ");
        }

        //add ASCII to tmp to print in end of line
        if (std::isprint(bytes[i])) {
            ascii[i % 16] = bytes[i];
        } else {
            ascii[i % 16] = '.';
        }

        //Add terminate symbol
        ascii[i % 16 + 1] = '\0';
    }

    // Pad to 16 chars
    while (i % 16 != 0) {
        printf ("   ");
        
        //print space in center
        if (i % 16 == 7) {
            printf(" ");
        }

        i++;
    }

    printf("   %s\n", ascii);
}

l1_packet sniffer::sniff() {
    l1_packet packet;
    packet.body = pcap_next(this->interface, &packet.header);
    return packet;
}

sniffer::~sniffer() {
    pcap_close(this->interface);
}