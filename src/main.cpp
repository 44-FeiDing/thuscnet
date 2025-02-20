#include "pcap.hpp"
#include <fstream>
#include <cmath>

using namespace std;
using namespace PCAP;

//fstream fin("test/1.in", istream::binary);
//fstream fout("test/1.out", ostream::binary);

int main()
{
    Pcap rec;
    cin >> rec;
    cout << rec.fuck_pcaprec_longer_than_1000();
}
