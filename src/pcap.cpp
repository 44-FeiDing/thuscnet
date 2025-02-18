#include "pcap.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ostream>
#include <vector>
using std::istream;
using std::ostream;

namespace PCAP {

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

    int Pcaprec_hdr::lenth() const
    {
        return incl_len;
    }

    istream & operator>>(istream & in, Pcaprec_hdr & data)
    {
        in.read((char*)&data, sizeof(Pcaprec_hdr));
        //std::cerr.write((char*)&data, sizeof(Pcaprec_hdr));
        //std::cerr << "\0";
        //std::cerr << "\0";
        //std::cerr << "\0";
        //std::cerr << "\0";
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

    int Pcaprec::lenth() const
    {
        return header.lenth();
    }

    istream & operator>>(istream & in, Pcaprec & data)
    {
        in >> data.header;
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

    istream & operator>>(istream & in, Pcap & data)
    {
        in >> data.header;
        while (!(in.eof()))
        {
            Pcaprec tmp;
            in >> tmp;
            data.data.push_back(tmp);
        }
        data.data.pop_back();
        return in;
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

    Pcap Pcap::fuck_pcaprec_longer_than_1000()
    {
        Pcap newpcap;
        newpcap.header = header;
        for (auto i:data)
            //if (i.lenth() <= 1000)
                newpcap.data.push_back(i);
        std::sort(newpcap.data.begin(), newpcap.data.end());
        std::cerr << data.size();
        return newpcap;
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

