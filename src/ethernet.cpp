#include "ethernet.hpp"
#include "utilities.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <netinet/in.h>
#include <vector>

namespace ETHERNET
{
    Ethernet_frame::Ethernet_frame(const std::vector<uint8_t> & src):
        dest_mac{src[0], src[1], src[2], src[3], src[4], src[5]},
        src_mac{src[6], src[7], src[8], src[9], src[10], src[11]},
        ether_type{uint16_t((src[12] << 8) + src[13])},
        data(src.begin() + 14, src.end() - 4),
        fcs{src.end()[-4], src.end()[-3], src.end()[-2], src.end()[-1]}
    {
        if (src.size() < 64)
        {
            std::cerr << "Fuck you." << std::endl;
            std::cerr << "Source data too small when construct ethernet ";
            return;
        }
    }

    uint64_t Ethernet_frame::query_check_byte(uint8_t x) const
    {
        static std::array<uint64_t, 256> mem{};
        static const uint64_t G = 0b100000100110000010001110110110111u; // NOTE: G has 33 bits!
        if (mem[x])
            return mem[x];
        if (x == 0)
            return 0;
        auto y = x;
        for (size_t i = 7; i < 8; i--)
        {
            if (x >> i & 1) {
                x ^= (G << i >> 32);
                mem[y] ^= (G << i);
            }
        }
        return mem[y];
    }

    std::array<uint8_t, 4> Ethernet_frame::calculate_fcs() const
    {
        std::vector<uint8_t> tmp;
        std::array<uint8_t, 4> res;

        tmp.insert(tmp.end(), dest_mac.begin(), dest_mac.end());
        tmp.insert(tmp.end(), src_mac.begin(), src_mac.end());
        tmp.push_back(ether_type >> 8);
        tmp.push_back(ntohs(ether_type) >> 8);
        tmp.insert(tmp.end(), data.begin(), data.end());
        tmp.push_back((uint8_t)0);
        tmp.push_back((uint8_t)0);
        tmp.push_back((uint8_t)0);
        tmp.push_back((uint8_t)0);

        for (auto &i : tmp)
            i = std::bit_reverse((uint8_t)i);
        for (size_t i = 0; i < 4; i++)
            tmp[i] = (~tmp[i]);
        for (size_t i = 4; i < tmp.size(); i++) {
            
            uint64_t g = query_check_byte(tmp[i - 4]);
            tmp[i - 4] ^= ( g >> 32 );
            tmp[i - 3] ^= (g >> 24);
            tmp[i - 2] ^= (g >> 16);
            tmp[i - 1] ^= (g >> 8);
            tmp[i] ^= g;
        } /* for (size_t i = 4; i < tmp.size(); i++) */
        for (size_t i = 0; i < 4; i++)
        {
            res[i] = std::bit_reverse(tmp.rbegin()[3 - i]);
            res[i] = ~res[i];
        }
        return res;
    }

    bool Ethernet_frame::verify() const
    {
        auto correct_fcs = this->calculate_fcs();
        // std::cerr.setf(std::ios::hex, std::ios::basefield);
        // std::cerr << "Ethernet frame: " << ((correct_fcs[0] << 24) | (correct_fcs[1] << 16) | (correct_fcs[2] << 8) | correct_fcs[3]) << std::endl;
        return correct_fcs == fcs;
    }
    std::vector<uint8_t> Ethernet_frame::get_data() const
    {
        return data;
    }
    uint16_t Ethernet_frame::get_type() const
    {
        return ether_type;
    }
}
