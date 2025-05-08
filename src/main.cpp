#include "ethernet.hpp"
#include "icmp.hpp"
#include "ip.hpp"
#include "pcap.hpp"
#include "utilities.hpp"
#include <cstddef>
#include <fstream>
#include <sys/types.h>
#include <vector>
std::ifstream fin("test/2.in");
std::ofstream fout("test/2.out");

int main()
{
    FEIDING::Pcap pcap;
    std::vector<std::vector<uint8_t>> res;
    std::vector<bool> replied(false);
    fin >> pcap;
    auto data = pcap.get_data();
    for (const auto &i : data)
    {
        FEIDING::Ethernet_frame ethernet(i);
        if (!ethernet.verify() || ethernet.get_type() != 0x0800)
        {
            replied.push_back(0);
            continue;
        }
        FEIDING::Ip ip(ethernet.get_data());
        if (!ip.verify() || !std::is_in_a_same_subnet(ip.get_src_and_dst_ip().first, ip.get_src_and_dst_ip().second))
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
    FEIDING::Pcap res_pcap(res);
    size_t j = 0, k = 0;
    for (const auto &i : pcap.data)
    {
        if (!replied[j])
        {
            j++;
            continue;
        }
        res_pcap.data[k].header.tsec = i.header.tsec;
        res_pcap.data[k].header.ts_usec = i.header.ts_usec + 1;
        if (res_pcap.data[k].header.ts_usec >= 1000000)
        {
            res_pcap.data[k].header.tsec++;
            res_pcap.data[k].header.ts_usec = 0;
        }
        k++;
    }
    fout << res_pcap;
}
