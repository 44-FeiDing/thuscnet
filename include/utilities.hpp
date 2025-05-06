#ifndef UTILITIES_HPP_
#define UTILITIES_HPP_
#include <array>
#include <cstdint>

namespace std
{
uint8_t bit_reverse(uint8_t);
template <typename T> uint32_t convert_to_uint32(const T &);
bool is_in_a_same_subnet(const std::array<uint8_t, 4> &, const std::array<uint8_t, 4> &);
} // namespace std

#endif
