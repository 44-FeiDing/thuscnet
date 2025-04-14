#include "arp.hpp"
#include "ethernet.hpp"
#include "pcap.hpp"
#include <iostream>
#include <vector>
int main()
{
    FEIDING::Pcap pcap;
    std::vector<std::vector<uint8_t>> res;
    std::cin >> pcap;
    for (const auto &i : pcap.get_data()) {
        FEIDING::Ethernet_frame frame(i);
        if (frame.get_type() == 0x0806 && frame.verify()) {
            FEIDING::Arp arp(frame.get_data());
            if (arp.get_type() == 1)
            {
                res.push_back(FEIDING::Ethernet_frame(arp.get_src_mac(), (*FEIDING::arp_table.find(arp.get_dest_ip())).second, 2, arp.get_original_data()).get_original_data());
            }
        }
    }
}
