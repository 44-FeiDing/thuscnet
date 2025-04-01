#include "ip.hpp"
#include <cstdint>
#include <netinet/in.h>
#include <vector>

namespace IP
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
        src_ip{src[12], src[13], src[14], src[15]},
        dest_ip{src[16], src[17], src[18], src[19]}
        {
            if (ihl > 5)
            {
                options.resize((ihl - 5) * 4);
                for (size_t i = 0; i < options.size(); ++i)
                {
                    options[i] = src[20 + i];
                }
            }
            else
            {
                options.resize(0);
            }
        }
    uint16_t Ipgroup_hdr::calculate_checksum()
    {
        std::vector<uint16_t> src;
        src.push_back((version << 4) + ihl);
        src.push_back(type);
        src.push_back(tot_length >> 8);
        src.push_back(tot_length & 0xff);
        src.push_back(identification >> 8);
        src.push_back(identification & 0xff);
        src.push_back((flag << 5) + (offset >> 8));
        src.push_back(offset & 0xff);
        src.push_back(ttl);
        src.push_back(protocal);
        src.push_back(0);
        src.push_back(0);
        for (auto i : src_ip)
        {
            src.push_back(i);
        }
        for (auto i : dest_ip)
        {
            src.push_back(i);
        }
        for (auto i : options)
        {
            src.push_back(i);
        }

        uint32_t sum = 0;
        for (size_t i = 0; i < src.size(); i += 2)
        {
            sum += (src[i] << 8) + src[i + 1];
            while (sum > 0xffffu)
            {
                sum = (sum & 0xffffu) + (sum >> 16);
            }
        }
        return (~sum) & 0xffffu;
    }
    bool Ipgroup_hdr::verify()
    {
        return calculate_checksum() == checksum;
    }
}
