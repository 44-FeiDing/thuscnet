#ifndef ARP_HPP_
#define ARP_HPP_
#include <array>
#include <cstdint>
#include <map>
#include <vector>
namespace FEIDING
{
    const std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> arp_table = {
        {{10, 2, 1, 1}, {0x98, 0x01, 0x29, 0, 0, 0x1}},
        {{10, 2, 2, 1}, {0x98, 0x01, 0x29, 0, 0, 0x2}},
        {{10, 2, 3, 1}, {0x98, 0x01, 0x29, 0, 0, 0x3}},
        {{10, 2, 4, 1}, {0x98, 0x01, 0x29, 0, 0, 0x4}},
        {{10, 2, 5, 1}, {0x98, 0x01, 0x29, 0, 0, 0x5}},
        {{10, 2, 6, 1}, {0x98, 0x01, 0x29, 0, 0, 0x6}},
        {{10, 2, 7, 1}, {0x98, 0x01, 0x29, 0, 0, 0x7}},
        {{10, 2, 8, 1}, {0x98, 0x01, 0x29, 0, 0, 0x8}},
        {{10, 2, 9, 1}, {0x98, 0x01, 0x29, 0, 0, 0x9}},
        {{10, 2, 10, 1}, {0x98, 0x01, 0x29, 0, 0, 0xa}},
        {{10, 2, 11, 1}, {0x98, 0x01, 0x29, 0, 0, 0xb}},
        {{10, 2, 12, 1}, {0x98, 0x01, 0x29, 0, 0, 0xc}},
        {{10, 2, 13, 1}, {0x98, 0x01, 0x29, 0, 0, 0xd}},
        {{10, 2, 14, 1}, {0x98, 0x01, 0x29, 0, 0, 0xe}},
        {{10, 2, 15, 1}, {0x98, 0x01, 0x29, 0, 0, 0xf}},
        {{10, 2, 16, 1}, {0x98, 0x01, 0x29, 0, 0, 0x10}},
// #ifndef ONLINE_JUDGE
//         {{10,2,12,82}, {0x98,0x01,0x29,0x00,0x00,114}},
// #endif
    };
    class Arp
    {
        private:
            uint16_t hw_type;
            uint16_t proto_type;
            uint8_t hlen;
            uint8_t plen;
            uint16_t op;
            std::array<uint8_t, 6> src_mac;
            std::array<uint8_t, 4> src_ip;
            std::array<uint8_t, 6> dest_mac;
            std::array<uint8_t, 4> dest_ip;
        public:
            Arp(const std::vector <uint8_t> &);
            Arp answer() const;
            bool get_type() const;
            const std::array<uint8_t, 4> & get_dest_ip() const;
            const std::array<uint8_t, 6> & get_src_mac() const;
            const std::vector<uint8_t> get_original_data() const;
    };
}
#endif
