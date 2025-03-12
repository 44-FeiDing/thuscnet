#include "ethernet.hpp"
#include <algorithm>
#include <cstdint>
#include <iostream>
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
        std::copy(src.begin()[14], src.end()[-4], data);
    }

    bool Ethernet::verify()
    {
        //
        return 0;
    }
}
