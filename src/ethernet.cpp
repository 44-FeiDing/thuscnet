#include "ethernet.hpp"
#include "utilities.hpp"
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <netinet/in.h>
#include <vector>

namespace ETHERNET
{
    Ethernet::Ethernet(const std::vector<uint8_t> & src):
        dest_mac{src[0], src[1], src[2], src[3], src[4], src[5]},
        src_mac{src[6], src[7], src[8], src[9], src[10], src[11]},
        ether_type{uint16_t((src[12] << 8) + src[13])},
        fcs{src.end()[-4], src.end()[-3], src.end()[-2], src.end()[-1]}
    {
        if (src.size() < 64)
        {
            std::cerr << "Fuck you." << std::endl;
            std::cerr << "Source data too small when construct ethernet ";
            return;
        }
        ether_type = ntohs(ether_type);
        std::copy(src.begin()[14], src.end()[-4], data);
    }

    bool Ethernet::verify()
    {
        std::vector<uint8_t> tmp;
        static const uint64_t G = 0b100000100110000010001110110110111;

        tmp.insert(tmp.end(), dest_mac.begin(), dest_mac.end());
        tmp.insert(tmp.end(), src_mac.begin(), src_mac.end());

        tmp.push_back(ntohs(ether_type) >> 8);
        tmp.push_back(ether_type >> 8);

        tmp.insert(tmp.end(), data.begin(), data.end());

        tmp.push_back((uint8_t)0);
        tmp.push_back((uint8_t)0);
        tmp.push_back((uint8_t)0);
        tmp.push_back((uint8_t)0);

        for (auto &i : tmp)
            i = std::bit_reverse(i);
        for (int i = 0; i < 4; i++)
            tmp[i] = (~tmp[i]);
        
        for (int i = 0; i < tmp.size() - 8; i++)
        {
            if (tmp)
        }
    }
}
