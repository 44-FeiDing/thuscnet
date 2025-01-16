#include "pcap.hpp"
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ostream>
using std::istream;
using std::ostream;

istream & PCAP::operator>>(istream & in, Pcap_hdr & data)
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

ostream & PCAP::operator<<(ostream & out, Pcap_hdr data)
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

int PCAP::Pcaprec_hdr::lenth() const
{
    return incl_len;
}

istream & PCAP::operator>>(istream & in, Pcaprec_hdr & data)
{
    in.read((char*)&data, sizeof(Pcaprec_hdr));
    data.incl_len = ntohl(data.incl_len);
    data.orig_len = ntohl(data.orig_len);
    data.tsec = ntohl(data.tsec);
    data.ts_usec = ntohl(data.ts_usec);
    return in;
}

ostream & PCAP::operator<<(ostream & out, Pcaprec_hdr data)
{
    data.incl_len = htonl(data.incl_len);
    data.orig_len = htonl(data.orig_len);
    data.tsec = htonl(data.tsec);
    data.ts_usec = htonl(data.ts_usec);
    out.write((char*)&data, sizeof(Pcaprec_hdr));
    return out;
}

int PCAP::Pcaprec::lenth() const
{
    return header.lenth();
}

istream & PCAP::operator>>(istream & in, Pcaprec & data)
{
    in >> data.header;
    data.data.resize(data.lenth());
    in.read((char*)data.data.data(), data.lenth());
    return in;
}

ostream & PCAP::operator<<(ostream & out, const Pcaprec & data)
{
    out << data.header;
    out.write((char*)data.data.data(), data.lenth());
    return out;
}

istream & PCAP::operator>>(istream & in, Pcap & data)
{
    in >> data.header;
    while (!(in.eof()))
    {
        Pcaprec tmp;
        in >> tmp;
        data.data.push_back(tmp);
    }
    return in;
}

ostream & PCAP::operator<<(ostream & out, const Pcap & data)
{
    out << data.header;
    for (auto const & i : data.data)
    {
        out << i;
    }
    return out;
}

void PCAP::Pcap::fuck_pcaprec_longer_than_1000()
{
    std::cout << data.size();
    bool *b = new bool[data.size()];
    memset(b, 0, data.size() * sizeof(bool));
    for (int i = 0; i < data.size(); i++)
    {
        if (data[i].lenth() > 1000)
            b[i] = 1;
    }
    unsigned l = 0, r = 0;
    while (r < data.size())
    {
        while (r < data.size() && b[r])
            r++;
        data[l] = data[r];
        l++;
        r++;
    }
    delete [] b;
}
