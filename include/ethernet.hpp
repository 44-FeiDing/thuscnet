#ifndef ETHERNET_HPP_
#define ETHERNET_HPP_
#include <array>
#include <cstdint>
#include <vector>
namespace FEIDING
{
class Ethernet_frame
{
  private:
    std::array<uint8_t, 6> dest_mac;
    std::array<uint8_t, 6> src_mac;
    uint16_t ether_type;
    std::vector<uint8_t> data;
    std::array<uint8_t, 4> fcs;

  public:
    Ethernet_frame(const std::vector<uint8_t> &);
    Ethernet_frame(const std::array<uint8_t, 6> &, const std::array<uint8_t, 6> &, const uint16_t &,
                   const std::vector<uint8_t> &);
    uint64_t query_check_byte(uint8_t) const;
    std::array<uint8_t, 4> calculate_fcs() const;
    bool verify() const;
    std::vector<uint8_t> get_data() const;
    uint16_t get_type() const;
    std::vector<uint8_t> get_original_data() const;
    std::array<uint8_t, 6> get_dest_mac() const
    {
        return dest_mac;
    }
    std::array<uint8_t, 6> get_src_mac() const
    {
        return src_mac;
    }
};
} // namespace FEIDING
#endif
