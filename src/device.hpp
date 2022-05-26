#ifndef __device
#define __device

#include <netinet/ether.h>
#include <pcap/pcap.h>
#include <memory>
#include <unordered_map>
#include <mutex>

#define pcap_timeout 30
#define maxDeviceNum 50
#define maxNameLen 20

struct Device{
    char name[maxNameLen];
    pcap_t* hdl;
    uint8_t mac[ETH_ALEN];
    uint ipaddr;
    uint ipmask;
    timeval timestamp;

    //std::mutex mtx;
    
    int over;
    //int refcount;
    //uint neibor_ipaddr;

    Device(const Device& d);
    Device();
    //void info_copy(const Device* d);
};
using device_share_ptr = std::shared_ptr<Device>;

int initDevice(device_share_ptr dev, pcap_if_t* nowdev);

extern device_share_ptr deviceTable[maxDeviceNum];
extern std::mutex device_mtx[maxDeviceNum];
extern int close_routing;
extern int empty_func();

#endif