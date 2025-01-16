#include "../include/pcap.hpp"
#include <iostream>
#include <cmath>

using namespace std;

int main()
{
    PCAP::Pcap rec;
    cin >> rec;
    rec.fuck_pcaprec_longer_than_1000();
    cout << rec;
}
