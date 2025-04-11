#include "arp.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace FEIDING
{
    Arp::Arp(const std::vector<uint8_t> &src):
        hw_type(src[0] << 8 | src[1]),
        proto_type(src[2] << 8 | src[3]),
        hlen(src[4]),
        plen(src[5]),
        op(src[6] << 8 | src[7]),
        src_mac({src[8], src[9], src[10], src[11], src[12], src[13]}),
        src_ip({src[14], src[15], src[16], src[17]}),
        dest_mac({src[18], src[19], src[20], src[21], src[22], src[23]}),
        dest_ip({src[24], src[25], src[26], src[27]})
    {}
    Arp Arp::answer() const
    {
        std::vector<uint8_t> res;
        res.push_back(hw_type >> 8);
        res.push_back(hw_type & 0xff);
        res.push_back(proto_type >> 8);
        res.push_back(proto_type & 0xff);
        res.push_back(hlen);
        res.push_back(plen);
        res.push_back(0);
        res.push_back(2);
        for (const auto &i : (*arp_table.find(dest_ip)).second)
            res.push_back(i);
        for (const auto &i : dest_ip)
            res.push_back(i);
        for (const auto &i : src_mac)
            res.push_back(i);
        for (const auto &i : src_ip)
            res.push_back(i);
        return Arp(res);
    }
    std::array<uint8_t, 6> Arp::get_dest_mac() const { return dest_mac; }
    std::array<uint8_t, 6> Arp::get_src_mac() const { return src_mac; }
    std::vector<uint8_t> Arp::get_data() const 
    {
        std::vector<uint8_t> res;
        res.push_back(hw_type >> 8);
        res.push_back(hw_type & 0xff);
        res.push_back(proto_type >> 8);
        res.push_back(proto_type & 0xff);
        res.push_back(hlen);
        res.push_back(plen);
        res.push_back(0);
        res.push_back(op & 0xff);
        for (const auto &i : src_mac)
            res.push_back(i);
        for (const auto &i : src_ip)
            res.push_back(i);
        for (const auto &i : dest_mac)
            res.push_back(i);
        for (const auto &i : dest_ip)
            res.push_back(i);
        return res;
    }
}
