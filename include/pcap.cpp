#include "pcap.hpp"
#include <iostream>
#include <cstdint>
#include <arpa/inet.h>
using namespace std;
using namespace PCAP;

istream & operator>>(istream & in, Pcap_hdr & data)
{
    in.read((char*)&data, sizeof(Pcap_hdr));
    data.magic_number = ntohl(data.magic_number);
    data.version_major = ntohs(data.version_major);
    return in;
}
