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
    char errbuf[PCAP_ERRBUF_SIZE+1];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        throw std::runtime_error(errbuf);
    }

    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        devs_vector.push_back(dev->name);
    }
    
    pcap_freealldevs(alldevs);

    return devs_vector;
}