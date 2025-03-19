#include "utilities.hpp"
#include <cstdint>
uint8_t std::bit_reverse(uint8_t x)
{
    uint8_t res;
    for (int i = 0; i < 8; i++)
        res = (res << 1) | (x & 1);
    return res;
}
