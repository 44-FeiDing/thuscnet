#!/usr/bin/env python3

from scapy.all import rdpcap, IP, ICMP

def extract_icmp_summary(pcap_file):
    packets = rdpcap(pcap_file)
    summaries = set()

    for pkt in packets:
        if IP in pkt and ICMP in pkt:
            ip_layer = pkt[IP]
            icmp_layer = pkt[ICMP]
            summary = (
                ip_layer.src,
                ip_layer.dst,
                icmp_layer.type,
                len(pkt)
            )
            summaries.add(summary)
    return summaries

def compare_pcaps(file1, file2):
    icmp1 = extract_icmp_summary(file1)
    icmp2 = extract_icmp_summary(file2)

    only_in_file1 = icmp1 - icmp2
    only_in_file2 = icmp2 - icmp1

    print(f"\n📁 {file1} 中独有的 ICMP 包:")
    for entry in sorted(only_in_file1):
        print(entry)

    print(f"\n📁 {file2} 中独有的 ICMP 包:")
    for entry in sorted(only_in_file2):
        print(entry)

if __name__ == "__main__":
    # 替换成你自己的 PCAP 文件路径
    compare_pcaps("test/2.ans", "test/2.out")
