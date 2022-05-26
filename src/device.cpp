#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <algorithm>
#include <string.h>
#include <netinet/ether.h>
#include <fcntl.h>
#include <assert.h>
#include <thread>
#include <memory>
#include <unistd.h>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_set>
#include "general.hpp"
#include "device.hpp"
#include "arp.hpp"
#include "packetio.hpp"
#include "iplayer.hpp"
#include "tcplayer.hpp"
#include "sock.hpp"
#include "tcp_timer.hpp"

using std::mutex;
using std::string;
using std::thread;
using std::unordered_map;
using std::unordered_set;

static unordered_set<string> allDevice __attribute__((init_priority(140)));
device_share_ptr deviceTable[maxDeviceNum] __attribute__((init_priority(131)));
mutex device_mtx[maxDeviceNum] __attribute__((init_priority(132)));

int close_routing = 0;

int getMac(device_share_ptr& dev);
int addDevice(device_share_ptr& dev);

/*Device::Device(const Device &d)
{
    memmove(name, d.name, strlen(d.name));
    memmove(mac, d.mac, ETH_ALEN);
    ipaddr = d.ipaddr;
    ipmask = d.ipmask;
    hdl = d.hdl;
    memmove(&timestamp, &d.timestamp, sizeof(timeval));

    over = 0;
    //neibor_ipaddr = 0;
}*/
Device::Device()
{
    memset(name, 0, sizeof(name));
    over = 0;
    gettimeofday(&timestamp, NULL);
    //timestamp.tv_sec = timestamp.tv_usec = 0;
}

/*void Device::info_copy(const Device *d)
{
    ipaddr = d->ipaddr;
    hdl = d->hdl;
    memmove(mac, d->mac, ETH_ALEN);
    ipmask = d->ipmask;
    memmove(name, d->name, strlen(d->name) + 1);
}*/

void sniffWorker(device_share_ptr ptr, int *over, int devid)
{
    pcap_loop(ptr->hdl, -1, receiveFrame, (uint8_t *)devid);
    //pcap_perror(ptr->hdl, "worker: ");
    *over = 1;
}

static void delDeviceData(device_share_ptr dev)
{
    for (uint8_t i = 0; i < routeTable_len; ++i)
    {
        DVtable_mtx[i].lock();
        for (auto &pair : DV_table[i])
        {
            if (strcmp(pair.second.dev->name, dev->name) == 0)
            {
                pair.second.cost = unreachable_cost;
            }
        }
        DVtable_mtx[i].unlock();

        routeTable_mtx[i].lock();
        for (auto p = routeTable[i].begin(); p != routeTable[i].end();)
        {
            if (strcmp(p->second.copy->name, dev->name) == 0)
            {
                p = routeTable[i].erase(p);
            }
            else
            {
                ++p;
            }
        }
        routeTable_mtx[i].unlock();
    }
}

void newDevice_start(pcap_if_t *devs)
{
    for (pcap_if_t *nowdev = devs; nowdev; nowdev = nowdev->next)
    {
        if (allDevice.count(nowdev->name))
        {
            continue;
        }
        device_share_ptr ptr(new Device);
        if (initDevice(ptr, nowdev) == 0)
        {
            for (int index = 0; index < maxDeviceNum; ++index)
            {

                device_mtx[index].lock();
                if (deviceTable[index])
                {
                    device_mtx[index].unlock();
                    continue;
                }
                deviceTable[index] = ptr;
                device_mtx[index].unlock();

                allDevice.insert(nowdev->name);

                int sum = 0;
                uint mask = ptr->ipmask;
                while (mask)
                {
                    sum += mask % 2;
                    mask = mask >> 1;
                }

                routeTable_mtx[sum].lock();
                routeTable[sum][ptr->ipmask & ptr->ipaddr].nexthop = 0;
                routeTable[sum][ptr->ipaddr & ptr->ipmask].copy = ptr;
                routeTable_mtx[sum].unlock();

                DVtable_mtx[sum].lock();
                DV_table[sum][ptr->ipaddr & ptr->ipmask] = DV_tableEntry{0, 0, ptr};
                DVtable_mtx[sum].unlock();

                thread t(sniffWorker, ptr, &ptr->over, index);
                t.detach();
                goto label;
            }
            assert(false);
        label:
            assert(true);
        }
    }
}

void manager()
{
    uint arp_clock = 0;
    while (1)
    {

        std::this_thread::sleep_for(std::chrono::seconds(3));
        int devid = 0, flags = 0;
        timeval now;
        gettimeofday(&now, NULL);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *devs;
        if (pcap_findalldevs(&devs, errbuf) != 0)
        {
            printf("%s\n", errbuf);
            return;
        }

        for (; devid < maxDeviceNum; ++devid)
        {
            if (!deviceTable[devid])
            {
                continue;
            }
            if (deviceTable[devid]->over == 1)
            { // bad device
                allDevice.erase(deviceTable[devid]->name);
                flags = 1;
                break;
            }
            else if (!close_routing && now.tv_sec - deviceTable[devid]->timestamp.tv_sec > DV_timeout && deviceTable[devid]->name != "lo")
            {
                delDeviceData(deviceTable[devid]);
                deviceTable[devid]->timestamp.tv_sec = now.tv_sec;
                deviceTable[devid]->timestamp.tv_usec = now.tv_usec;
            }
            else
            {
                /*for (pcap_if_t *nowdevs = devs; nowdevs; nowdevs = nowdevs->next)   ip change ?
                {
                     // TODO
                }*/
            }
        }
        if (flags)
        {
            delDeviceData(deviceTable[devid]);
            device_mtx[devid].lock();
            deviceTable[devid].reset();
            device_mtx[devid].unlock();
        }
        newDevice_start(devs);
        pcap_freealldevs(devs);

        if (close_routing)
        {
            goto next;
        }
        for (int i = 0; i < maxDeviceNum; ++i)
        {
            if (deviceTable[i] && deviceTable[i]->name != "lo")
            {
                send_DV_msg(deviceTable[i]);
            }
        }
    next:
        if ((arp_clock++ % 10) == 0)
        {
            arpTable_mtx.lock();
            for (auto p = arpTable.begin(); p != arpTable.end();)
            {
                if (now.tv_sec > p->second.timestamp.tv_sec + arp_timeout)
                    p = arpTable.erase(p);
                else
                {
                    for (int i = 0; i < maxDeviceNum; ++i)
                    {
                        if ((deviceTable[i]->ipaddr & deviceTable[i]->ipmask) == (deviceTable[i]->ipmask & p->first))
                        {
                            sendArp(p->first, deviceTable[i]);
                            break;
                        }
                    }
                    ++p;
                }
            }
            arpTable_mtx.unlock();
        }
        unique_lock lock(sockmap_mtx);
        for (auto p = fd_to_sock.begin(); p != fd_to_sock.end();)
        {
            if (p->second->status == tcp_status::ORPHAN) // no mutex is safe
                p = fd_to_sock.erase(p);
            else
                ++p;
        }
    }
}

void __attribute__((constructor(65000))) init()
{
    timeval now_time;
    gettimeofday(&now_time, NULL);
    init_seq_engine.seed((uint64_t)now_time.tv_sec); // initialize random engine
    hint_port = (init_seq_engine() % (high_port - low_port + 1)) + low_port;

    char errbuf[PCAP_ERRBUF_SIZE];
    int ret = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
    if (ret != 0)
    {
        printf("%s\n", errbuf);
        exit(-1);
    }
    pcap_if_t *devs;
    if (pcap_findalldevs(&devs, errbuf) != 0)
    {
        printf("%s\n", errbuf);
        exit(-1);
    }

    int index = 0;
    for (pcap_if_t *nowdev = devs; nowdev; nowdev = nowdev->next)
    {
        device_share_ptr ptr(new Device);
        if (initDevice(ptr, nowdev) == 0)
        {
            deviceTable[index] = ptr;
            allDevice.insert(nowdev->name);

            int sum = 0;
            uint mask = ptr->ipmask;
            while (mask)
            {
                sum += mask % 2;
                mask = mask >> 1;
            }

            routeTable[sum].emplace(ptr->ipmask & ptr->ipaddr, entry{ptr, 0});
            DV_table[sum].emplace(ptr->ipaddr & ptr->ipmask, DV_tableEntry{0, 0, ptr});

            thread t(sniffWorker, deviceTable[index], &ptr->over, index);
            t.detach();
            index++;
        }
    }
    pcap_freealldevs(devs);

    thread t(manager);
    t.detach();
    thread m(clock_manager);
    m.detach();
    //printf("init successfully\n");
}

int initDevice(device_share_ptr device, pcap_if_t *nowdev)
{
    memmove(device->name, nowdev->name, std::min((int)strlen(nowdev->name) + 1, maxNameLen - 1)); // get dev->name
    if (getMac(device) != 0)
    { // get dev->mac
        return -1;
    }

    for (pcap_addr *devaddr = nowdev->addresses; devaddr; devaddr = devaddr->next) // get dev->ipaddr, ipmask
    {
        if (devaddr->addr->sa_family == AF_INET)
        {
            sockaddr_in *skaddr_in = (sockaddr_in *)devaddr->addr;
            device->ipaddr = little2big<int>(skaddr_in->sin_addr.s_addr);
        }
        if (devaddr->netmask && devaddr->netmask->sa_family == AF_INET)
        {
            sockaddr_in *skaddr_in = (sockaddr_in *)devaddr->netmask;
            device->ipmask = little2big<int>(skaddr_in->sin_addr.s_addr);
        }
    }
    if (addDevice(device) != 0)
    { // get dev->pcap_t
        return -1;
    }
    return 0;
}

// need dev->name, get dev->hdl
int addDevice(device_share_ptr& dev)
{
    pcap_t *handle = pcap_create(dev->name, nullptr);
    if (handle == nullptr)
    {
        return -1;
    }
    if (pcap_set_snaplen(handle, 65535) != 0)
    {
        pcap_close(handle);
        return -1;
    }
    if (pcap_set_timeout(handle, pcap_timeout) != 0)
    {
        pcap_close(handle);
        return -1;
    }
    if (pcap_set_promisc(handle, 0) != 0)
    { // don't need promiscuous mode
        pcap_close(handle);
        return -1;
    }
    if (pcap_activate(handle) != 0)
    {
        //pcap_perror(handle, "error:");
        pcap_close(handle);
        return -1;
    }
    if (pcap_setdirection(handle, PCAP_D_IN) != 0)
    { // only capture received packet
        pcap_close(handle);
        return -1;
    }
    int *dlt, num;
    num = pcap_list_datalinks(handle, &dlt);
    if (dlt == NULL)
    {
        pcap_close(handle);
        return -1;
    }
    for (int i = 0; i < num; ++i)
    {
        if (dlt[i] == DLT_EN10MB)
        {
            pcap_set_datalink(handle, DLT_EN10MB);
            pcap_free_datalinks(dlt);
            goto set;
        }
    }
    pcap_free_datalinks(dlt);
    pcap_close(handle);
    return -1;

set:
    dev->hdl = handle;
    return 0;
}

// need to have dev->name, get dev->mac
int getMac(device_share_ptr& dev)
{
    char tmp[100];
    sprintf(tmp, "/sys/class/net/%s/address", dev->name);
    FILE *f = fopen(tmp, "r");
    if (f == NULL)
    {
        return -1;
    }
    int x[ETH_ALEN];
    fscanf(f, "%x:%x:%x:%x:%x:%x", x, x + 1, x + 2, x + 3, x + 4, x + 5);
    for (int j = 0; j < ETH_ALEN; ++j)
    {
        dev->mac[j] = x[j];
    }
    //devCanUse[devid] = true;
    return 0;
}

int empty_func()
{
    return 0;
}