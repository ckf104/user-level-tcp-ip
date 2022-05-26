#include <pcap/pcap.h>
#include <string.h>
#include <stdio.h>
#include "general.hpp"
#include "device.hpp"
#include "iplayer.hpp"
#include "arp.hpp"
#include <netinet/ether.h>
//using frameReceiveCallback = int (*)(const void* pkt, int len, int devid);

// buf need preserve header space
// ether_header is not included in len parameter
int sendFrame(void * buf, int len, uint16_t ethtype, const void * destmac, const void* srcmac, pcap_t* hdl){
    ether_header* header = (ether_header*)buf;   
    memmove(header->ether_dhost, destmac, ETH_ALEN);
    memmove(header->ether_shost, srcmac, ETH_ALEN);
    header->ether_type = little2big<uint16_t>(ethtype);
    
    //deviceTable[id]->mtx.lock();    // i don't know if pacp_inject is thread safe
    int ret = pcap_inject(hdl, buf, sizeof(ether_header) + len);
    if(ret == sizeof(ether_header) + len){
        //deviceTable[id]->mtx.unlock();
        return 0;  
    }
    else if(ret == PCAP_ERROR){
        //deviceTable[id]->mtx.unlock();
        pcap_perror(hdl, "error: ");
        return not_a_good_device;
    }
    else{
        //deviceTable[id]->mtx.unlock();
        pcap_perror(hdl, "error: ");
        return -1; 
    }
};

// need reentrant
void receiveFrame(uint8_t* args, const pcap_pkthdr* pkthdr, const uint8_t* data){
    //printf("get a packet\n");
    int devid = (int)(int64_t(args));
    device_share_ptr dev_ptr;
    device_mtx[devid].lock();
    if(!deviceTable[devid]){
        device_mtx[devid].unlock();
        return;
    }
    else{
        dev_ptr = deviceTable[devid];
        device_mtx[devid].unlock();
    }

    const ether_header *hdr = (const ether_header*)data;
    if(hdr->ether_type == little2big<uint16_t>(arpType)){
        receiveArp(data + sizeof(ether_header), pkthdr->caplen - sizeof(ether_header), dev_ptr, &pkthdr->ts);
    }
    else if(hdr->ether_type == little2big<uint16_t>(ipType)){
       receive_ipPkt(data + sizeof(ether_header), pkthdr->caplen - sizeof(ether_header), &pkthdr->ts, dev_ptr);
    }

}