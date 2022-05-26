#include <string.h>
#include <iostream>
#include <assert.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <vector>
#include <mutex>
#include "device.hpp"
#include "iplayer.hpp"
#include "packetio.hpp"
#include "arp.hpp"
#include "general.hpp"
#include "tcplayer.hpp"

static volatile uint16_t ip_indentifier = 0x10;

unordered_map<uint, entry> routeTable[routeTable_len] __attribute__((init_priority(123)));
mutex routeTable_mtx[routeTable_len] __attribute__((init_priority(134)));

int lmp_find(uint dstip, uint *nextip, device_share_ptr &copy) // longest prefix match
{
    for (int i = routeTable_len - 1; i >= 0; --i)
    {
        uint mask = ~((1 << (routeTable_len - 1 - i)) - 1);
        routeTable_mtx[i].lock();
        if (routeTable[i].count(mask & dstip) == 0)
        {
            routeTable_mtx[i].unlock();
            continue;
        }
        if ((mask & dstip) == dstip && (i < routeTable_len - 2))
        {                               // all 0 in local host bit means network id
            routeTable_mtx[i].unlock(); // exception for 31 and 32
            continue;
        }
        if (nextip != NULL)
        {
            *nextip = routeTable[i][dstip & mask].nexthop;
        }
        //uint devid = routeTable[i][dstip & mask].devid;
        copy = routeTable[i][dstip & mask].copy;

        routeTable_mtx[i].unlock();
        return 0;
    }
    return unreachable;
}

/*mac_addr is mac addr of next hop, devid is corresponding device*/
int find_nextMac(uint dstip, uint8_t mac_addr[ETH_ALEN], device_share_ptr &copy)
{
    uint nextip;
    if (lmp_find(dstip, &nextip, copy) != 0)
    {
        return unreachable;
    }
    /*if(*devid == 0xffffffff){
        *devid = en.devid;
    }*/
    nextip = nextip == 0 ? dstip : nextip;
    timeval now;
    gettimeofday(&now, NULL);

    arpTable_mtx.lock();
    if (arpTable.count(nextip) == 0)
    {
        arpTable_mtx.unlock();
        sendArp(nextip, copy);
        return no_mac_in_table;
    }
    /*else if (now.tv_sec - arpTable[nextip].timestamp.tv_sec > arp_timeout)
    {
        arpTable.erase(nextip);
        arpTable_mtx.unlock();
        sendArp(nextip, copy);
        return no_mac_in_table;
    }*/
    memmove(mac_addr, arpTable[nextip].v, ETH_ALEN);
    arpTable_mtx.unlock();
    return 0;
}

// caller reserves space for ip header and ethenet header
int sendipPkt(uint saddr, int upper_pro, uint8_t *buf, int len, uint dstip /*=0xffffffff*/, uint8_t ttl /*=default*/, device_share_ptr dev /*null*/)
{ // when sending broadcast packet, caller determines dev

    uint8_t mac_addr[ETH_ALEN];
    device_share_ptr copy;
    if (dstip != broad_ipaddr)
    {
        int ret = find_nextMac(dstip, mac_addr, copy);
        if (ret != 0 || copy->ipaddr != saddr)
        {
            return ret;
        }
    }
    else
    {
        memset(mac_addr, 0xff, ETH_ALEN);
    }
    iphdr *hdr = (iphdr *)(buf + sizeof(ether_header));
    hdr->saddr = little2big<uint>(saddr); // for retransmission of tcp
    hdr->daddr = little2big<uint>(dstip);
    hdr->version = IPVERSION;
    hdr->ihl = sizeof(iphdr) / 4;
    hdr->tos = 0;
    hdr->tot_len = little2big<uint16_t>(len + sizeof(iphdr));
    hdr->id = little2big<uint16_t>(__sync_fetch_and_add(&ip_indentifier, 1));
    hdr->frag_off = 0;
    hdr->ttl = ttl;
    hdr->protocol = upper_pro;
    hdr->check = 0;
    hdr->check = getChecksum((uint16_t *)hdr, sizeof(iphdr) / sizeof(uint16_t));
    // the input is big endianness, so no need to change byte order here

    int rel;
    if (dstip == broad_ipaddr)
    {
        rel = sendFrame(buf, len + sizeof(iphdr), ipType, mac_addr, dev->mac, dev->hdl);
    }
    else
    {
        rel = sendFrame(buf, len + sizeof(iphdr), ipType, mac_addr, copy->mac, copy->hdl);
    }
    //printf("rel: %d\n", rel);
    return 0;
}

// pktlen doesn't have to be equal to hdr->tol_len because of padded bytes
static int forward(const uint8_t *data, uint pktlen)
{
    iphdr *hdr = (iphdr *)data;
    if (hdr->ttl == 0)
    {
        return ttl_expire;
    }
    uint dstip = little2big<uint>(hdr->daddr);
    device_share_ptr copy;
    uint8_t mac_addr[ETH_ALEN];

    int ret = find_nextMac(dstip, mac_addr, copy);
    if (ret != 0)
    {
        return ret;
    }

    uint8_t *buf = (uint8_t *)malloc(pktlen + sizeof(ether_header));
    memmove(buf + sizeof(ether_header), data, pktlen);

    hdr = (iphdr *)(buf + sizeof(ether_header));
    hdr->check = 0;
    hdr->ttl -= 1;
    hdr->check = getChecksum((uint16_t *)hdr, sizeof(iphdr) / sizeof(uint16_t));
    sendFrame(buf, pktlen, ipType, mac_addr, copy->mac, copy->hdl);

    free(buf);
    return 0;
}

// first is a ipheader in data
int receive_ipPkt(const uint8_t *data, uint pktlen, const timeval *timestamp, device_share_ptr copy)
{
    int i = 0;
    iphdr *hdr = (iphdr *)data;

    if (check((const uint16_t *)data, sizeof(iphdr) / sizeof(uint16_t)) == 0)
    { // checksum is correct ?
        return corrupted_pkt;
    }
    if (hdr->ihl != 5)
    { // not support ip option
        return 0;
    }

    if (little2big<uint16_t>(hdr->frag_off) & IP_OFFMASK != 0 || little2big<uint16_t>(hdr->frag_off) & IP_MF != 0)
    {
        return fragment_ip_pkt;
    }
    if (hdr->daddr == broad_ipaddr)
    {
        goto get;
    }

    for (int i = 0; i < maxDeviceNum; ++i)
    {
        device_mtx[i].lock();
        if (deviceTable[i] && deviceTable[i]->ipaddr == little2big<uint>(hdr->daddr))
        {
            device_mtx[i].unlock();
            goto get;
        }
        device_mtx[i].unlock();
    }
    return forward(data, pktlen);
get:
    if (hdr->protocol == routeType && hdr->daddr == broad_ipaddr)
    {
        receiveRoutingPkt(data + sizeof(iphdr), little2big<uint>(hdr->saddr), pktlen - sizeof(iphdr), timestamp, copy);
    }
    else if (hdr->protocol == tcpType)
    {
        rcv_tcp_packet(little2big<uint>(hdr->daddr), little2big<uint>(hdr->saddr), data + sizeof(iphdr), pktlen - sizeof(iphdr));
    }
    //printf("get a pkt from %x\n", little2big<uint>(hdr->saddr));
    return 0;
}

/*following code is about routing*/

unordered_map<uint, DV_tableEntry> DV_table[routeTable_len] __attribute__((init_priority(150))); // subnet node -> cost, nexthop addr, device
mutex DVtable_mtx[routeTable_len] __attribute__((init_priority(151)));

int update_DV_table(const DV_data_entry *data, int len, device_share_ptr copy, uint nexthop_ipaddr) // little endinness
{
    using std::vector;
    vector<uint> update_addr;
    vector<uint8_t> update_masklen;
    vector<uint8_t> update_cost;
    int flags = 0;

    for (int i = 0; i < len; ++i)
    {
        uint dst_ipaddr = little2big<uint>(data[i].dst);
        uint8_t dst_ipmask = data[i].mask_len;
        uint8_t new_cost = uint8_t(data[i].cost + 1) == 0 ? unreachable_cost : data[i].cost + 1;

        DVtable_mtx[dst_ipmask].lock();
        if (DV_table[dst_ipmask].count(dst_ipaddr) == 0)
        {
            DV_table[dst_ipmask].emplace(dst_ipaddr, DV_tableEntry{new_cost, nexthop_ipaddr, copy});
            if (new_cost != unreachable_cost)
            {
                update_addr.push_back(dst_ipaddr);
                update_masklen.push_back(dst_ipmask);
                update_cost.push_back(new_cost);
            }
        }
        else if (DV_table[dst_ipmask][dst_ipaddr].cost > new_cost || DV_table[dst_ipmask][dst_ipaddr].nexthop == nexthop_ipaddr)
        { // from the same device
            uint mask = ~((1 << (routeTable_len - dst_ipmask - 1)) - 1);
            if ((dst_ipaddr & mask) == (copy->ipaddr & copy->ipmask) && mask == copy->ipmask)
            {
                DV_table[dst_ipmask][dst_ipaddr] = DV_tableEntry{0, 0, copy};
                routeTable_mtx[dst_ipmask].lock();
                routeTable[dst_ipmask][dst_ipaddr] = entry{copy, 0};
                routeTable_mtx[dst_ipmask].unlock();
            }
            else
            {
                DV_table[dst_ipmask][dst_ipaddr].cost = new_cost;
                DV_table[dst_ipmask][dst_ipaddr].nexthop = nexthop_ipaddr;
                DV_table[dst_ipmask][dst_ipaddr].dev = copy;
                update_addr.push_back(dst_ipaddr);
                update_masklen.push_back(dst_ipmask);
                update_cost.push_back(new_cost);
            }
        }
        DVtable_mtx[dst_ipmask].unlock();
    }

    for (int i = 0, leng = update_addr.size(); i < leng; ++i)
    {
        uint dst_ipaddr = update_addr[i];
        uint8_t dst_ipmask = update_masklen[i];
        uint8_t dst_cost = update_cost[i];
        routeTable_mtx[dst_ipmask].lock();
        if (dst_cost == unreachable_cost)
        {
            routeTable[dst_ipmask].erase(dst_ipaddr);
        }
        else
        {
            routeTable[dst_ipmask][dst_ipaddr].nexthop = nexthop_ipaddr;
            routeTable[dst_ipmask][dst_ipaddr].copy = copy;
        }
        routeTable_mtx[dst_ipmask].unlock();
    }
    return 0;
}

// predefined little endianed hdr except hdr->length and hdr->check = 0
int send_DV_msg(device_share_ptr copy, uint next_hop_addr) // reversed poison ?
{
    vector<DV_data_entry> data;

    for (uint8_t i = 0; i < routeTable_len; ++i)
    {
        DVtable_mtx[i].lock();
        for (const auto &en : DV_table[i]) // i -> dst ipmask, en.first -> dst ipaddr
        {
            if (strcmp(en.second.dev->name, copy->name) != 0 || en.second.nexthop == 0)
            {
                data.push_back(DV_data_entry{little2big<uint>(en.first), i, en.second.cost});
            }
        }
        DVtable_mtx[i].unlock();
    }

    uint8_t *buf = (uint8_t *)malloc(sizeof(ether_header) + sizeof(iphdr) + sizeof(DV_hdr) + data.size() * sizeof(DV_data_entry));
    memmove(buf + sizeof(ether_header) + sizeof(iphdr) + sizeof(DV_hdr), data.data(), sizeof(DV_data_entry) * data.size());

    DV_hdr *hdr = (DV_hdr *)(buf + sizeof(ether_header) + sizeof(iphdr));
    hdr->length = little2big<uint16_t>((uint16_t)data.size());
    hdr->check = 0;
    hdr->check = getChecksum((uint16_t *)hdr, (sizeof(DV_hdr) + data.size() * sizeof(DV_data_entry)) / sizeof(uint16_t));

    sendipPkt(copy->ipaddr, routeType, buf, sizeof(DV_hdr) + data.size() * sizeof(DV_data_entry), next_hop_addr, default_ttl, copy);
    free(buf);
    return 0;
}

int receiveRoutingPkt(const uint8_t *data, uint next_hop_addr, uint caplen, const timeval *timestamp, device_share_ptr copy)
{
    const DV_hdr *hdr = (const DV_hdr *)data;
    uint leng = little2big<uint16_t>(hdr->length) * sizeof(DV_data_entry) + sizeof(DV_hdr);
    if (leng > caplen)
    {
        return corrupted_pkt;
    }
    else if (check((const uint16_t *)data, leng / sizeof(uint16_t)) == 0)
    {
        return corrupted_pkt;
    }

    copy->timestamp.tv_sec = timestamp->tv_sec;
    copy->timestamp.tv_usec = timestamp->tv_usec;

    update_DV_table((const DV_data_entry *)(data + sizeof(DV_hdr)), little2big<uint16_t>(hdr->length), copy, next_hop_addr);

    return 0;
}

void printRoutingTable()
{
    for (int i = routeTable_len - 1; i >= 0; --i)
    {
        routeTable_mtx[i].lock();
        for (auto &pair : routeTable[i])
        {
            uint8_t id1 = *(uint8_t *)&pair.first;
            uint8_t id2 = *((uint8_t *)&pair.first + 1);
            uint8_t id3 = *((uint8_t *)&pair.first + 2);
            uint8_t id4 = *((uint8_t *)&pair.first + 3);
            uint8_t next1 = *((uint8_t *)&pair.second.nexthop + 0);
            uint8_t next2 = *((uint8_t *)&pair.second.nexthop + 1);
            uint8_t next3 = *((uint8_t *)&pair.second.nexthop + 2);
            uint8_t next4 = *((uint8_t *)&pair.second.nexthop + 3);

            printf("net id: %x.%x.%x.%x , length of mask: %i, nexthop: %x.%x.%x.%x\n",
                   id4, id3, id2, id1, i, next4, next3, next2, next1);
        }
        routeTable_mtx[i].unlock();
    }
}

void setRoutingTable(int mask_len, uint addr, uint nexthop)
{
    device_mtx[0].lock();
    device_share_ptr p = deviceTable[0];
    device_mtx[0].unlock();

    routeTable_mtx[mask_len].lock();
    routeTable[mask_len][addr] = entry{p, nexthop};
    routeTable_mtx[mask_len].unlock();
}

void close_routing_func()
{
    close_routing = 1;
}