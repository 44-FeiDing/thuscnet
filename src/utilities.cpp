#include "utilities.hpp"
#include <cstdint>
uint8_t std::bit_reverse(uint8_t x)
{
    uint8_t res;
    for (int i = 0; i < 8; i++)
        res = (res << 1) | ((x >> i) & 1);
    return res;
}

template <typename T> uint32_t std::convert_to_uint32(const T &a)
{
    uint32_t res;
    for (const auto &i : a)
    {
        res <<= 8;
        res |= i;
    }
    return res;
}
