#include <string.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <malloc.h>
#include <mutex>
#include "general.hpp"
#include "packetio.hpp"
#include "device.hpp"
#include "arp.hpp"

using std::mutex;

mutex arpTable_mtx __attribute__((init_priority(124)));
unordered_map<uint, macaddr> arpTable __attribute__((init_priority(125)));
uint8_t broadcastMac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/*void macaddr::operator=(const macaddr &b)
{
    memmove(v, b.v, ETH_ALEN);
}*/
macaddr::macaddr(const timeval* tstp, const uint8_t mac[ETH_ALEN])
{
    memmove(v, mac, ETH_ALEN);
    timestamp.tv_sec = tstp->tv_sec;
    timestamp.tv_usec = tstp->tv_usec;
}
macaddr::macaddr()
{
    memset(v, 0, ETH_ALEN);
    gettimeofday(&timestamp, NULL);
}

struct ip_arphdr
{
    unsigned short int ar_hrd; /* Format of hardware address.  */
    unsigned short int ar_pro; /* Format of protocol address.  */
    unsigned char ar_hln;      /* Length of hardware address.  */
    unsigned char ar_pln;      /* Length of protocol address.  */
    unsigned short int ar_op;  /* ARP opcode (command).  */
    /* Ethernet looks like this : This bit is variable sized
       however...  */
    unsigned char __ar_sha[ETH_ALEN]; /* Sender hardware address.  */
    uint __ar_sip;                    /* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN]; /* Target hardware address.  */
    uint __ar_tip;                    /* Target IP address.  */
} __attribute__((packed));

void sendArp(uint tar_ip, device_share_ptr& copy)
{
    ip_arphdr hdr;
    hdr.ar_hrd = little2big<uint16_t>(ARPHRD_ETHER);
    hdr.ar_pro = little2big<uint16_t>(ipType);
    hdr.ar_hln = ETH_ALEN;
    hdr.ar_pln = ipaddr_len;
    hdr.ar_op = little2big<uint16_t>(ARPOP_REQUEST);
    memmove(hdr.__ar_sha, copy->mac, ETH_ALEN);
    uint big_tar_ip = little2big<uint>(tar_ip), big_devip = little2big<uint>(copy->ipaddr);
    memmove(&hdr.__ar_sip, &big_devip, ipaddr_len);
    memset(hdr.__ar_tha, 0, sizeof(ETH_ALEN));
    memmove(&hdr.__ar_tip, &big_tar_ip, ipaddr_len);

    char *buf = (char *)malloc(sizeof(ether_header) + sizeof(ip_arphdr));
    memmove(buf + sizeof(ether_header), &hdr, sizeof(ip_arphdr));
    sendFrame(buf, sizeof(ip_arphdr), arpType, broadcastMac, copy->mac, copy->hdl);
    free(buf);
}

// first is a arp header in data
void receiveArp(const uint8_t *data, uint pktlen, device_share_ptr copy, const timeval* timestamp)
{
    /*if(pktlen != sizeof(ip_arphdr)){
        printf("bad arp packet!, %d\n", pktlen);
        return;
    }*/
    // may get padded 0 in tail
    ip_arphdr *receiveArpHrd = (ip_arphdr *)data;
    if (receiveArpHrd->ar_hrd != little2big<uint16_t>((uint16_t)ARPHRD_ETHER) || receiveArpHrd->ar_pro != little2big<uint16_t>(uint16_t(ipType)))
    {
        printf("not supported arp packet");
        return;
    }

    arpTable_mtx.lock(); // to guarantee thread safety
    arpTable[little2big<uint>(receiveArpHrd->__ar_sip)] = macaddr{timestamp, receiveArpHrd->__ar_sha};
    arpTable_mtx.unlock();

    //printf("receive a arp: %x:%x:%x:%x:%x:%x, %d\n", receiveArpHrd->__ar_sha[0], receiveArpHrd->__ar_sha[1],
    //receiveArpHrd->__ar_sha[2], receiveArpHrd->__ar_sha[3], receiveArpHrd->__ar_sha[4], receiveArpHrd->__ar_sha[5], receiveArpHrd->__ar_sip);
    if (receiveArpHrd->ar_op == little2big<uint16_t>((uint16_t)ARPOP_REQUEST) && little2big<uint>(receiveArpHrd->__ar_tip) == copy->ipaddr)
    {
        char *buf = (char *)malloc(sizeof(ether_header) + sizeof(ip_arphdr));
        memmove(buf + sizeof(ether_header), receiveArpHrd, sizeof(ip_arphdr));
        ip_arphdr *sendArpHrd = (ip_arphdr *)(buf + sizeof(ether_header));
        sendArpHrd->ar_op = little2big<uint16_t>(ARPOP_REPLY);
        memmove(sendArpHrd->__ar_sha, copy->mac, ETH_ALEN);
        memmove(sendArpHrd->__ar_tha, receiveArpHrd->__ar_sha, ETH_ALEN);
        sendArpHrd->__ar_sip = little2big<uint>(copy->ipaddr);
        sendArpHrd->__ar_tip = receiveArpHrd->__ar_sip;
        sendFrame(buf, sizeof(ip_arphdr), arpType, receiveArpHrd->__ar_sha, copy->mac, copy->hdl);
        free(buf);
    }
}
