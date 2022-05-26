#ifndef __general
#define __general
// for general purpose

/*constexpr int timeout = 20;
constexpr int maxDeviceNum = 50;
constexpr int maxNameLen = 20;*/
#include <malloc.h>
#include <string.h>
#include <algorithm>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <shared_mutex>
#include <mutex>
#include <random>
#include <memory>
#include <chrono>

using std::shared_mutex;
using std::mutex;
using std::shared_lock;
using std::unique_lock;
using std::mt19937;

#define not_a_good_device -2 // the device now can not be used
#define no_mac_in_table -3   // now can not ipaddr->macaddr
#define unreachable -4       // dst ip is not in routeTable
#define ttl_expire -5        // may need a icmp ?
#define corrupted_pkt -6
#define fragment_ip_pkt -7
#define unknown_connect_request -8
#define busy_connect_request -9
#define busy_sockfd         -10
#define out_of_order_data   -11
#define out_of_window_data  -12
#define stale_data          -13

#define routeType 25
#define arpType 0x0806
#define ipType 0x0800
#define tcpType 0x6

#define broad_ipaddr 0xffffffff
#define unreachable_cost 0xff
#define DV_interval  3
#define DV_timeout   30
#define arp_timeout 60

#define default_ttl 100
#define ipaddr_len 4
#define routeTable_len 33

#define tcp_buffer_len  65536
#define init_sock_fd    1000
#define default_rto    1    // 500ms
#define default_mss    1460
#define low_port  35000
#define high_port 60000

#define rto_limit 128
#define rw_timeout 120

template <class T>
T little2big(T value)
{
    int size = sizeof(T);
    T ret;
    for (int i = 0; i < size; ++i)
    {
        *((unsigned char *)&ret + i) = *((unsigned char *)&value + size - 1 - i);
    }
    return ret;
}

template <uint size>
void little2big(uint8_t *ptr)
{
    for (int i = 0, j = size - 1; i < j; ++i, --j)
    {
        uint8_t tmp = *(ptr + i);
        *(ptr + i) = *(ptr + j);
        *(ptr + j) = tmp;
    }
}

/*enum class intersect_status{
    unintersect,
    left,
    mid,
    right,
};*/

uint16_t getChecksum(const uint16_t *p, int len, uint base=0, uint padding=0); // the array length of p
bool check(const uint16_t *p, int len, uint base=0, uint padding=0);           // the array length of p
std::pair<uint, uint> judge(uint big_left, uint big_right, uint small_left, uint small_right);

extern "C" int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
extern "C" int __wrap_freeaddrinfo(addrinfo *rel);

#endif