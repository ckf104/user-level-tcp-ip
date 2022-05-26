#include <pcap/pcap.h>
#include "../src/device.hpp"
#include "../src/packetio.hpp"
#include "../src/general.hpp"
#include "../src/arp.hpp"
#include "../src/iplayer.hpp"
#include <iostream>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
using std::cerr;
using std::cout;
using std::endl;

uint8_t dstmac[ETH_ALEN] = {0, 0x50, 0x56, 0xc0, 0, 0x8};
const char saddr[] = "192.168.31.141";
const char daddr[] = "192.168.31.1";
const char deviceName[] = "ens33";

int main(int argc, char *argv[]) // argv[1] -> saddr, argv[2] -> daddr, argv[3] -> send pkt
{
    while (1)
    {
        empty_func();
    }
    //sendArp(0xc0a81f01, 0);
    //cout << "ret: " << ret << endl;
    return 0;
}