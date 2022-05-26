#ifndef __iplayer
#define __iplayer

#include <unordered_map>
#include <vector>
#include <mutex>
#include <netinet/ip.h>
#include "device.hpp"
#include "general.hpp"

using std::mutex;
using std::unordered_map;
using std::vector;

struct entry // nexthop equaling to 0.0.0.0 means local network
{
    device_share_ptr copy;
    uint nexthop;
};

extern unordered_map<uint, entry> routeTable[routeTable_len];
extern std::mutex routeTable_mtx[routeTable_len];

int lmp_find(uint dstip, uint *nextip, device_share_ptr &copy);

int sendipPkt(uint saddr, int upper_pro, uint8_t *buf, int len, uint dstip = broad_ipaddr, uint8_t ttl = default_ttl, device_share_ptr dev = device_share_ptr());
int receive_ipPkt(const uint8_t *data, uint pktlen, const timeval *timestamp, device_share_ptr copy);
void printRoutingTable();
void setRoutingTable(int mask_len, uint addr, uint nexthop);

int send_DV_msg(device_share_ptr copy, uint next_hop_addr=broad_ipaddr);
void close_routing_func();
/*following code is about routing*/

struct DV_tableEntry
{
    uint8_t cost;
    uint nexthop;
    device_share_ptr dev;
};

struct hop_entry
{
    timeval timestamp; // last time get pkt from this hop
    //uint dev_ipaddr;    // my dev ipaddr as this hop's neighbor
    uint nexthop_addr;
    uint seq;          // now seq number used by this hop
    bool is_ack;       // my latest route entry has been acked by this hop ?
    bool need_rst;     // when get a hop_entry, need_rst = 1, get a ack, need_rst = 0
    uint8_t ack_times; // when need_rst = 1, ack_times = 3, decrease 1 when get a ack
};

struct DV_hdr
{
    uint check : 16;
    uint length : 16;
} __attribute__((packed));

struct DV_data_entry
{
    //timeval timestamp;
    uint dst;
    uint8_t mask_len;
    uint8_t cost;
} __attribute__((packed));

extern unordered_map<uint, DV_tableEntry> DV_table[routeTable_len];
extern mutex DVtable_mtx[routeTable_len];

int receiveRoutingPkt(const uint8_t *data, uint next_hop_addr, uint caplen, const timeval *timestamp, device_share_ptr copy);
#endif