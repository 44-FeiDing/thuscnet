#ifndef ETHERNET_HPP_
#define ETHERNET_HPP_
#include <array>
#include <cstdint>
#include <istream>
#include <ostream>
#include <vector>
using std::istream;
using std::ostream;
namespace ETHERNET {
    class Ethernet
    {
        private:
            std::array<uint8_t, 6> dest_mac;
            std::array<uint8_t, 6> src_mac;
            uint16_t ether_type;
            std::vector<uint8_t> data;
            std::array<uint8_t, 4> fcs;
        public:
            Ethernet(const std::vector<uint8_t> &);
            bool verify();
    }__attribute__((packed));
}
#endif
