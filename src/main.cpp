#include "pcap.hpp"
#include "ethernet.hpp"
#include "ip.hpp"
#include <iostream>

int main()
{
    using namespace std;
    using namespace FEIDING;
    Pcap data;
    cin >> data;
    auto recs = data.get_data();
    for (auto &i : recs) {
        Ethernet_frame frame(i);
        if (frame.verify())
        {
            if (frame.get_type() == 0x0800)
            {
                Ipgroup_hdr ipgroup(frame.get_data());
                if (ipgroup.verify())
                    cout << "Yes" << endl;
                else
                    cout << "No" << endl;
            }
            else
                cout << "Yes" << endl;
        }
        else
            cout << "No" << endl;
    }
    return 0;
}
