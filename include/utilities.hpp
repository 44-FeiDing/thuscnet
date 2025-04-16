#ifndef UTILITIES_HPP_
#define UTILITIES_HPP_
#include <cstdint>

namespace std
{
uint8_t bit_reverse(uint8_t);
template <typename T> uint32_t convert_to_uint32(const T &);
} // namespace std

#endif
