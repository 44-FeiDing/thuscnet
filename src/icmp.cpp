#include "icmp.hpp"
#include <cstdint>
#include <vector>

namespace FEIDING
{
Icmp::Icmp(const uint8_t &src_type, const uint8_t &src_code, const std::vector<uint8_t> &src_data)
    : type(src_type), code(src_code), data(src_data)
{
}
Icmp::Icmp(const std::vector<uint8_t> &src) : type(src[0]), code(src[1]), data(src.begin() + 8, src.end())
{
}
Icmp Icmp::construct_reply() const
{
    return Icmp(0, 0, data);
}
const std::vector<uint8_t> &Icmp::get_data() const
{
    return data;
}
std::vector<uint8_t> Icmp::get_origin_data() const
{
    std::vector<uint8_t> res;
    res.push_back(type);
    res.push_back(code);
    for (int i = 0; i < 6; i++)
        res.push_back(0);
    for (const auto &i : data)
    {
        res.push_back(i);
    }
    return res;
}
} // namespace FEIDING
