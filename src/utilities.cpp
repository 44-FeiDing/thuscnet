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
bool std::is_in_a_same_subnet(const std::array<uint8_t, 4> &ip1, const std::array<uint8_t, 4> &ip2)
{
    return (ip1[0] == ip2[0]) && (ip1[1] == ip2[1]) && (ip1[2] == ip2[2]);
}
