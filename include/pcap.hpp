#ifndef PCAP_HPP_
#define PCAP_HPP_
#include <cstdint>
#include <iostream>
#include <vector>
using std::istream;
using std::ostream;
namespace PCAP
{
    class Pcap_hdr
    {
    private:
        // 所有字段都是大端序
        uint32_t magic_number;// 用于文件类型识别，始终为 0xA1B2C3D4，
        uint16_t version_major;// 始终为 2
        uint16_t version_minor;// 始终为 4
        int32_t thiszone;// 始终为 0
        uint32_t sigfigs;// 始终为 0
        uint32_t snaplen;// 允许的最大包长度，始终为 262144
        uint32_t network;// 数据类型，本次学习题中始终为 1 （以太网）
    public:
        friend istream & operator>>(istream & in, Pcap_hdr & data);
        friend ostream & operator<<(ostream & out, Pcap_hdr data);
    }__attribute__ ((packed));

    class Pcaprec_hdr
    {
    private:
        // 所有字段都是大端序
        uint32_t tsec;// 时间戳（秒）
        uint32_t ts_usec;// 时间戳（微秒）
        uint32_t incl_len;// 该片段的存储长度
        uint32_t orig_len;// 该片段实际的长度
    public:
        uint32_t lenth() const;
        uint64_t time() const;
        friend istream & operator>>(istream & in, Pcaprec_hdr & data);
        friend ostream & operator<<(ostream & out, Pcaprec_hdr data);
    }__attribute__ ((packed));

    class Pcaprec
    {
    private:
        Pcaprec_hdr header;
        std::vector<uint8_t> data;
    public:
        bool verify() const;
        uint32_t lenth() const;
        friend istream & operator>>(istream & in, Pcaprec & data);
        friend ostream & operator<<(ostream & out, const Pcaprec & data);
        friend bool operator<(const Pcaprec, const Pcaprec);
    };
    class Pcap
    {
    private:
        Pcap_hdr header;
        std::vector<Pcaprec> data;
    public:
        friend istream & operator>>(istream & in, Pcap & data);
        friend ostream & operator<<(ostream & out, const Pcap & data);
    };
}
#endif
