#include "pcap.hpp"
#include "ethernet.hpp"
#include <iostream>
#include <fstream>

std::ifstream fin("test/1.in");

int main()
{
    using namespace std;
    using namespace PCAP;
    using namespace ETHERNET;
    Pcap data;
    fin >> data;
    auto recs = data.get_data();
    for (auto &i : recs) {
        Ethernet_frame frame(i);
        if (frame.verify())
            cout << "Yes" << endl;
        else
            cout << "No" << endl;
    }
    return 0;
}
