#ifndef __arp
#define __arp

#include <unordered_map>
#include "device.hpp"

using std::unordered_map;

struct macaddr{
    timeval timestamp;
    uint8_t v[ETH_ALEN];
    //void operator=(const macaddr& b);
    macaddr(const timeval* timestamp, const uint8_t mac[ETH_ALEN]);
    macaddr();
};



extern unordered_map<uint, macaddr> arpTable;
extern std::mutex arpTable_mtx;
void sendArp(uint tar_ip, device_share_ptr& copy);
void receiveArp(const uint8_t* data, uint pktlen, device_share_ptr copy, const timeval* timestamp);

#endif