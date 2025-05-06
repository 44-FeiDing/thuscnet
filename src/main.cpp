#include "ethernet.hpp"
#include "icmp.hpp"
#include "ip.hpp"
#include "pcap.hpp"
#include "utilities.hpp"
#include <fstream>
std::ifstream fin("test/1.in");
std::ofstream fout("test/1.out");

int main()
{
    FEIDING::Pcap pcap, res;
    fin >> pcap;
    auto data = pcap.get_data();
    for (const auto &i : data)
    {
        FEIDING::Ethernet_frame ethernet(i);
        if (!ethernet.verify() || ethernet.get_type() != 0x0800)
        {
            continue;
        }
        FEIDING::Ip ip(ethernet.get_data());
        if (!ip.verify() || std::is_in_a_same_subnet(ip.get_src_and_dst_ip().first, ip.get_src_and_dst_ip().second))
        {
            continue;
        }
        FEIDING::Icmp icmp(ip.get_data());
        icmp = icmp.construct_reply();
        ip res()
    }
}
