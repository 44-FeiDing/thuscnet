#ifndef IP_HPP_
#define IP_HPP_

#include <array>
#include <cstdint>
#include <vector>

namespace ip
{
    class Ipgroup_hdr
    {
        private:
        uint8_t version;
        uint8_t ihl;
        uint8_t type;
        uint16_t tot_length;
        uint16_t identification;
        uint8_t flag;
        uint16_t offset;
        uint8_t ttl;
        uint8_t protocal;
        uint16_t checksum;
        std::array<uint8_t, 4> src_ip, dest_ip;

        public:
        Ipgroup_hdr(std::vector<uint8_t>);
    };
}

#endif
