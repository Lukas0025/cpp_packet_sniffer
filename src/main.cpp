/**
 * Project: packet sniffer - IPK variant ZETA
 * main (TOP) implemenation file
 * @author Lukáš Plevač <xpleva07> (BUT FIT)
 * @date 19.4.2021
 */

#include "sniffer.h"
#include <string.h>
#include <getopt.h> //getopt_long
#include <iostream> //print_f
#include <time.h>
#include <stdio.h>

typedef struct {
    std::string interface;
    bool        inited         = false;
    std::string port;
    bool        tcp            = false;
    bool        udp            = false;
    bool        icmp           = false;
    bool        arp            = false;
    bool        filter         = false;
    int         count          = 1;
} config;

const struct option longopts[] = {
    {"help",      no_argument,        0, 'h'},
    {"tcp",       no_argument,        0, 't'},
    {"udp",       no_argument,        0, 'u'},
    {"interface", required_argument,  0, 'i'},
    {"arp",       no_argument,        0, 'a'},
    {"icmp",      no_argument,        0, 'y'},
    {0,0,0,0},
};

void print_time() {
    
    time_t now = time(NULL);
    struct tm *tm;
    int off_sign;
    int off;

    if ((tm = localtime(&now)) == NULL) {
        return;
    }
    
    off_sign = '+';
    
    off = (int) tm->tm_gmtoff;

    if (tm->tm_gmtoff < 0) {
        off_sign = '-';
        off = -off;
    }

    printf("%d-%d-%dT%02d:%02d:%02d%c%02d:%02d",
           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
           tm->tm_hour, tm->tm_min, tm->tm_sec,
           off_sign, off / 3600, off % 3600);
}

void help() {
    printf("Packet sniffer with basic filters support\n\n");
    printf("./ipk-sniffer [-i interface_name | --interface interface_name] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n\n");
    printf("parameters:\n");
    printf("-i, --interface  - interface from sniff packets if empty print list of interfaces\n");
    printf("-p               - if set filter by port in src or dsc.\n");
    printf("-t, --tcp        - filter only TCP packets (SHOW)\n");
    printf("-u, --udp        - filter only UDP packets (SHOW)\n");
    printf("--icmp           - filter only ICMPv4 and ICMPv6 packets (SHOW)\n");
    printf("--arp            - filter only ARP packets (SHOW)\n");
    printf("-n               - number of packets to sniff, if not set is used 1\n");
    printf("-h, --help       - print this\n");
}

void print_if() {
    auto devs = sniffer::devices();

    for (auto name = devs.begin(); name != devs.end(); name++) {
        printf("%s\n", (*name).c_str());
    }
}

int main(int argc, char * argv[]) {
    config session;

    //get cli parametrs
    int c, option_index;
    while ((c = getopt_long(argc, argv, "i:p:tun:h", longopts, &option_index)) != -1) {
        switch (c) {
            case 'i': 
                session.interface = optarg;
                session.inited = true;
                continue;
            case 'p': 
                session.port = optarg;
                continue;
            case 't':
                session.tcp = true;
                session.filter = true;
                continue;  
            case 'u':
                session.udp = true;
                session.filter = true;
                continue;   
            case 'a':
                session.arp = true;
                session.filter = true;
                continue;   
            case 'y':
                session.icmp = true;
                session.filter = true;
                continue;
            case 'n':
                session.count = atoi(optarg);
                continue;
            case 'h':
                continue;
            default:
                if (optopt == 'i') {
                    session.inited = true;
                } else {
                    return 1;
                }
        }
    }

    //interface is not set
    if (!session.inited) {
        help();
        return 0;
    }
    
    //interface is set but its empty
    if (session.interface.empty()) {
        printf("\ninterfaces list for argument:\n\n");
        print_if();
        return 0;
    }

    //init sniffer on interface
    sniffer *session_sniffer;
    try {
        session_sniffer = new sniffer(session.interface);
    } catch (std::runtime_error& e) {
        fprintf(stderr, "[error] when try open sniffer: %s\n", e.what());
        return 1;
    }

    if (!session.port.empty()) {
        std::string filter;

        filter  = "port ";
        filter += session.port;

        session_sniffer->set_filter(filter);
    }

    for (int i = 0; i < session.count; i++) {
        auto l1_pack = session_sniffer->sniff();
        auto l3_pack = session_sniffer->l3_decode(l1_pack);
        int protocol = session_sniffer->get_protocol(l3_pack);

        //no TCP, UDP, ARP or ICMP
        if (protocol != IPPROTO_TCP &&
            protocol != IPPROTO_UDP &&
            protocol != IPPROTO_ICMP &&
            protocol != IPPROTO_ICMPV6 &&
            protocol != ARP_PROT) {
            i--;
            continue;
        }

        //filter by protocol type
        if (session.filter) {
            if ((!session.tcp  && protocol == IPPROTO_TCP) ||
                (!session.udp  && protocol == IPPROTO_UDP) ||
                (!session.icmp && protocol == IPPROTO_ICMP) ||
                (!session.icmp && protocol == IPPROTO_ICMPV6) ||
                (!session.arp  && protocol == ARP_PROT)) {
                    i--;
                    continue;
                }
        }

        auto l4_pack = session_sniffer->l4_decode(l3_pack);

        //print main info: %s %s : %d > %s : %d, length %d bytes
        //printf("%s", (date::format("%FT%TZ", time_point_cast<milliseconds>(system_clock::now()))).c_str()); 
        print_time();
        printf(" %s", session_sniffer->get_src(l3_pack).c_str());
        
        if (!l3_pack.arp && !l4_pack.icmp) {
            printf(" : %u", session_sniffer->get_src_port(l4_pack));
        }

        printf(" > ");
        printf("%s", session_sniffer->get_dst(l3_pack).c_str());
        
        if (!l3_pack.arp && !l4_pack.icmp) {
            printf(" : %u",  session_sniffer->get_dst_port(l4_pack));
        }
        
        printf(", length %d bytes\n", l1_pack.header.len);

        session_sniffer->hex_dump(l1_pack.body, l1_pack.header.len);
        printf("\n");
    }

    delete session_sniffer;
    
    return 0;
}