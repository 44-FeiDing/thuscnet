#include "arp.hpp"
#include "ethernet.hpp"
#include "icmp.hpp"
#include "ip.hpp"
#include "pcap.hpp"
#include "utilities.hpp"
#include <array>
#include <cstdint>
#include <fstream>
#include <map>
#include <sys/types.h>
#include <utility>
#include <vector>
// std::ifstream fin("test/2.in");
// std::ofstream fout("test/2.out");

int main()
{
    FEIDING::Pcap pcap;
    std::vector<std::vector<uint8_t>> res;
    std::cin >> pcap;
    std::vector<std::pair<uint32_t, uint32_t>> time(pcap.get_time());
    std::vector<bool> replied;
    auto data = pcap.get_data();

    for (auto &i : time)
    {
        i.second++;
        if (i.second == 1000000)
        {
            i.first++;
            i.second = 0;
        }
    }

    std::map<std::array<uint8_t, 6>, std::array<uint8_t, 4>> arp_table_swaped;
    for (const auto &i : FEIDING::arp_table)
    {
        arp_table_swaped[i.second] = i.first;
    }

    for (const auto &i : data)
    {
        FEIDING::Ethernet_frame ethernet(i);
        if (!ethernet.verify() || ethernet.get_type() != 0x0800)
        {
            replied.push_back(0);
            continue;
        }
        FEIDING::Ip ip(ethernet.get_data());
        if (!ip.verify() || !std::is_in_a_same_subnet(ip.get_src_and_dst_ip().first, ip.get_src_and_dst_ip().second) ||
            ip.get_protocol() != 1 || !FEIDING::arp_table.contains(ip.get_src_and_dst_ip().second) ||
            !arp_table_swaped.contains(ethernet.get_dest_mac()))
        {
            replied.push_back(0);
            continue;
        }
        FEIDING::Icmp icmp(ip.get_data());
        icmp = icmp.construct_reply();
        FEIDING::Ip res_ip(ip.get_src_and_dst_ip().second, ip.get_src_and_dst_ip().first,
                           20 + icmp.get_origin_data().size(), icmp.get_origin_data());
        res.push_back(FEIDING::Ethernet_frame(ethernet.get_src_mac(), ethernet.get_dest_mac(), (u_int16_t)0x0800,
                                              res_ip.get_origin_data())
                          .get_original_data());
        replied.push_back(1);
    }
    auto it = time.begin();
    for (const auto &i : replied)
    {
        if (!i)
        {
            const auto tmp = it - 1;
            time.erase(it);
            it = tmp;
        }
        it++;
    }
    std::cout << FEIDING::Pcap(res, time);
}
