#ifndef __packetio
#define __packetio

#include <pcap/pcap.h>
//#include <netinet/ether.h>

//using frameReceiveCallback = int (*)(const void* pkt, int len, int devid);
int sendFrame(void * buf, int len, uint16_t ethtype, const void * destmac, const void* srcmac, pcap_t* hdl);
void receiveFrame(uint8_t* handle, const pcap_pkthdr* pkthdr, const uint8_t* data);
//int setFrameReceiveCallback(frameReceiveCallback handle);

#endif