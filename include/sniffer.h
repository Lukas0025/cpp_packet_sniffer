/**
 * Project: packet sniffer - IPK variant ZETA
 * sniffer TOP Header file
 * @author Lukáš Plevač <xpleva07> (BUT FIT)
 * @date 19.4.2021
 */
#pragma once

#include <pcap/pcap.h>
#include <string>
#include <vector>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

typedef struct {
    //raw pcap data
    struct pcap_pkthdr header;
    const u_char *body;
} l1_packet;

typedef struct {
    //Decoded info
    bool ipv4 = false;
    bool ipv6 = false;

    //IP Headers
    struct ip6_hdr* ipv6_hdr;
    struct ip*      ipv4_hdr;

    //body
    const u_char *body;
    uint body_len;
} l3_packet;

class sniffer {
    public:
        /**
         * Returns list of available interfaces names in string
         * @return list of names of interfaces
         */
        static std::vector<std::string> devices();

        /**
         * Print hexdump of binary
         * @param bytes - bytes from print
         * @param len - len of print
         * @return void
         */
        static void hex_dump (const u_char* bytes, const int len);

        /**
         * L3 decoder (ETHERNET from L2 and IP from L3
         * @param packet - L1 packet to decode
         * @return L3 packet
         */
        l3_packet l3_decode(l1_packet packet);

        /**
         * Return src IP of l3 packet
         * @param packet - l3 packet
         * @return string of src IP address
         */
        std::string get_src(l3_packet packet);

        /**
         * Return dsc IP of l3 packet
         * @param packet - l3 packet
         * @return string of dsc IP address
         */
        std::string get_dst(l3_packet packet);
        
        /**
         * Object conscructor create sniffer object on interface
         * @param interface - name of interface
         * @return sniffer object
         */
        sniffer(std::string interface);

        /**
         * Set filter to sniffer
         */
        void set_filter(std::string filter);
        
        /**
         * Sniff one packet from interface
         * @return sniffed_packet
         */
        l1_packet sniff();

    private:
        pcap_t *interface;
        bpf_u_int32 mask;		/* The netmask of our sniffing device */
        bpf_u_int32 net;        /* Net of interface */
};
