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

class sniffer {
    public:
        /**
         * Returns list of available interfaces names in string
         * @return list of names of interfaces
         */
        static std::vector<std::string> devices();
};
