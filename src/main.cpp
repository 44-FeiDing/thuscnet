#include "pcap.hpp"
#include "ethernet.hpp"
#include <iostream>

int main()
{
    using namespace std;
    using namespace PCAP;
    using namespace ETHERNET;
    Pcap data;
    cin >> data;
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
