#include "ethernet.hpp"
#include <cstdint>
#include <iostream>
#include <vector>

namespace ETHERNET
{
    Ethernet::Ethernet(const std::vector<uint8_t> & src)
    {
        if (src.size() < 64)
        {
            std::cerr << "Source data too small when construct ethernet ";
            return;
        }
        //to be continue...
    }
}
