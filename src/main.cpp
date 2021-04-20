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

typedef struct {
    std::string interface;
    bool   inited         = false;
    int    port           = -1;
    bool   tcp            = false;
    bool   udp            = false;
    bool   icmp           = false;
    bool   arp            = false;
    bool   filter         = false;
    int    count          = 1;
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
                session.port = atoi(optarg);
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

    //session_sniffer->set_filter("port 22");

    for (int i = 0; i < session.count; i++) {
        auto l1_pack = session_sniffer->sniff();
        auto l3_pack = session_sniffer->l3_decode(l1_pack);

        //print main info
        printf(
            "%s %s : %d > %s : %d, length %d bytes\n",
            "time", //time
            session_sniffer->get_src(l3_pack).c_str(), //src IP
            0, // src port
            session_sniffer->get_dst(l3_pack).c_str(), //dst IP
            0, //dst port
            l1_pack.header.len //packet len in bytes
        );

        session_sniffer->hex_dump(l1_pack.body, l1_pack.header.len);
        printf("\n");
    }

    delete session_sniffer;
    
    return 0;
}