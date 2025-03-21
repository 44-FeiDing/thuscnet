#include "ip.hpp"
#include <cstdint>
#include <netinet/in.h>
#include <vector>

namespace ip
{
    Ipgroup_hdr::Ipgroup_hdr(std::vector<uint8_t> src):
        version(0b0100),
        ihl(src[0] & 0xfu),
        type(src[1]),
        tot_length((src[2] << 8) + src[3]),
        identification((src[4] << 8) + src[5]),
        flag(0b010),
        offset((src[6] & 0xbbbbbu << 8) + src[7]),
        ttl(src[8]),
        protocal(src[9]),
        checksum((src[10] << 8) + src[11]),
        dest_ip{src[12], src[13], src[14], src[15]},
        dest_ip{src[16], src[17]}// to be continue
}
