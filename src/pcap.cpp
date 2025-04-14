#include "pcap.hpp"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ostream>
#include <vector>
using std::istream;
using std::ostream;

namespace FEIDING
{
    Pcap_hdr::Pcap_hdr():
        magic_number(0xA1B2C3D4),
        version_major(2),
        version_minor(4),
        thiszone(0),
        sigfigs(0),
        snaplen(262144),
        network(1)
    {}

    istream & operator>>(istream & in, Pcap_hdr & data)
    {
        in.read((char*)&data, sizeof(Pcap_hdr));
        data.magic_number = ntohl(data.magic_number);
        data.version_major = ntohs(data.version_major);
        data.version_minor = ntohs(data.version_minor);
        data.thiszone = ntohl(data.thiszone);
        data.sigfigs = ntohl(data.sigfigs);
        data.snaplen = ntohl(data.snaplen);
        data.network = ntohl(data.network);
        return in;
    }

    ostream & operator<<(ostream & out, Pcap_hdr data)
    {
        data.magic_number = htonl(data.magic_number);
        data.version_major = htons(data.version_major);
        data.version_minor = htons(data.version_minor);
        data.thiszone = htonl(data.thiszone);
        data.sigfigs = htonl(data.sigfigs);
        data.snaplen = htonl(data.snaplen);
        data.network = htonl(data.network);
        out.write((char*)&data, sizeof(Pcap_hdr));
        return out;
    }

    uint32_t Pcaprec_hdr::lenth() const
    {
        return incl_len;
    }

    istream & operator>>(istream & in, Pcaprec_hdr & data)
    {
        in.read((char*)&data, sizeof(Pcaprec_hdr));
        data.incl_len = ntohl(data.incl_len);
        data.orig_len = ntohl(data.orig_len);
        data.tsec = ntohl(data.tsec);
        data.ts_usec = ntohl(data.ts_usec);
        return in;
    }

    ostream & operator<<(ostream & out, Pcaprec_hdr data)
    {
        data.incl_len = htonl(data.incl_len);
        data.orig_len = htonl(data.orig_len);
        data.tsec = htonl(data.tsec);
        data.ts_usec = htonl(data.ts_usec);
        out.write((char*)&data, sizeof(Pcaprec_hdr));
        return out;
    }

    Pcaprec::Pcaprec()// to be continue

    uint32_t Pcaprec::lenth() const
    {
        return header.lenth();
    }

    istream & operator>>(istream & in, Pcaprec & data)
    {
        in >> data.header;
        if (data.lenth() > (uint32_t)262144)
            return in;
        data.data.resize(data.lenth());
        in.read((char*)data.data.data(), data.lenth());
        return in;
    }

    ostream & operator<<(ostream & out, const Pcaprec & data)
    {
        out << data.header;
        out.write((char*)data.data.data(), data.lenth());
        return out;
    }

    std::vector<std::vector<uint8_t>> Pcap::get_data() const
    {
        std::vector<std::vector<uint8_t>> res;
        for (auto &i : data)
            res.push_back(i.get_data());
        return res;
    }

    istream & operator>>(istream & in, Pcap & data)
    {
        in >> data.header;
        while (!in.eof())
        {
            Pcaprec tmp;
            in >> tmp;
            data.data.push_back(tmp);
        }
        data.data.pop_back();
        return in;
    }

    Pcap::Pcap()
    {}

    Pcap::Pcap(const std::vector<std::vector<uint8_t>> & src):
        header()
    {
        for (const auto &i : src) {
            data.push_back(Pcaprec(i));
        }
    }

    ostream & operator<<(ostream & out, const Pcap & data)
    {
        out << data.header;
        for (auto const & i : data.data)
        {
            out << i;
        }
        return out;
    }

    uint64_t Pcaprec_hdr::time() const
    {
        return tsec*(uint64_t)1e6 + ts_usec;
    }

    bool operator<(const Pcaprec a, const Pcaprec b)
    {
        return a.header.time() < b.header.time();
    }
}

