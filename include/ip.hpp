#ifndef IP_HPP_
#define IP_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace FEIDING
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
    std::vector<uint8_t> options;

  public:
    Ipgroup_hdr(std::vector<uint8_t>);
    Ipgroup_hdr(const std::array<uint8_t, 4> &, const std::array<uint8_t, 4> &, const size_t &);
    uint16_t calculate_checksum();
    bool verify();
    std::vector<uint8_t> get_origin_data() const;
    uint8_t get_protocol() const
    {
        return protocal;
    }
    uint16_t get_tot_length() const
    {
        return tot_length;
    }
    uint8_t get_ihl() const
    {
        return ihl;
    }
    std::pair<std::array<uint8_t, 4>, std::array<uint8_t, 4>> get_src_and_dst_ip() const
    {
        return std::make_pair(src_ip, dest_ip);
    }
};
class Ip
{
  private:
    Ipgroup_hdr header;
    std::vector<uint8_t> payload;

  public:
    Ip(const std::vector<uint8_t> &);
    std::vector<uint8_t> get_origin_data() const;
    Ip(const std::array<uint8_t, 4> &src_ip, const std::array<uint8_t, 4> &dest_ip, const size_t length,
       const std::vector<uint8_t> &src_payload)
        : header(src_ip, dest_ip, length), payload(src_payload)
    {
        payload.resize(length - header.get_ihl() * 4);
    }
    uint16_t calculate_checksum()
    {
        return header.calculate_checksum();
    }
    uint8_t get_protocol() const
    {
        return header.get_protocol();
    }
    bool verify()
    {
        return header.verify();
    }
    std::vector<uint8_t> get_data() const
    {
        return payload;
    }
    std::pair<std::array<uint8_t, 4>, std::array<uint8_t, 4>> get_src_and_dst_ip() const
    {
        return header.get_src_and_dst_ip();
    }
};
} // namespace FEIDING

#endif
