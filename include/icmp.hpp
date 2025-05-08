#ifndef ICMP_HPP_
#define ICMP_HPP_

#include <cstdint>
#include <vector>

namespace FEIDING
{
class Icmp
{
  private:
    uint8_t type, code;
    static constexpr uint16_t checksum = 0;
    static constexpr uint32_t rest = 0;
    std::vector<uint8_t> data;

  public:
    Icmp(const uint8_t &, const uint8_t &, const std::vector<uint8_t> &);
    Icmp(const std::vector<uint8_t> &);
    Icmp construct_reply() const;
    const std::vector<uint8_t> &get_data() const;
    std::vector<uint8_t> get_origin_data() const;
};
} // namespace FEIDING

#endif
