# lab2b report

## code layout

```bash
$tree
├── checkpoint4
│   ├── v1.pcapng            # no extra file is needed for checkpoint 3 and 5
│   └── v6.pcapng
├── checkpoint6
│   └── v4.pcapng
├── readme.pdf
├── src
│   ├── arp.cpp
│   ├── arp.hpp
│   ├── build
│   ├── CMakeLists.txt
│   ├── device.cpp
│   ├── device.hpp
│   ├── general.cpp
│   ├── general.hpp
│   ├── iplayer.cpp
│   ├── iplayer.hpp
│   ├── packetio.cpp
│   └── packetio.hpp
└── test               # test program
    ├── try
    ├── try2
    ├── try2.cpp
    ├── try3
    ├── try3.cpp
    └── try.cpp
```

To get libsrc.so, using the following command in the build directory.

```bash
$camke ..
$make
```

To get try, try2, try3, using the following command in test directory.

```bash
$g++ -g -o try try.cpp -L../src/build -lsrc -lpcap -lpthread
$g++ -g -o try2 try2.cpp -L../src/build -lsrc -lpcap -lpthread
$g++ -g -o try3 try3.cpp -L../src/build -lsrc -lpcap -lpthread
```

To run these test programs, `LD_LIBRARY_PATH` need to be set properly. 

## Writing Task 1

Based on rfc826, I implement the ARP protocol to map IP address of next hop into mac address. Setting time limit of a ARP table entry as 30 seconds to adapt change of mac address. source code can be found in src/arp.cpp.

## Writing Task 2

My routing algorithm is based on DV vector algorithm. All nodes exchange information of reachable subnet periodically. 

![packet format](C:\Users\24147\Downloads\未命名文件.png)

Above picture shows the format of routing packet. Using IP protocol, upper protocol number is 25(reserved number in rfc standards). checksum is calculated by Using IP payload to protect integrity of routing data. Length is to record number of DV_data_entry. The following is format of DV_data_entry(src/iplayer.hpp). 

```c
struct DV_data_entry
{
    uint dst;           // network identifier of a reachable subnet
    uint8_t mask_len;   // subnet mask length
    uint8_t cost;
} __attribute__((packed));
```

 we consider the subnet unreachable When cost == 0xff. Next, I will clarify some key issues.

* **How to find neighbors?**

  because each host doesn't know IP address of neighbor first, So I decide to use broadcast IP address in destination field of IP header(mac address of destination too). Of course, source field in IP header is IP address of host's corresponding device. When a host receives a IP packet whose destination is broadcast IP address and upper protocol number is 25, the host will consider it as a routing packet and update its DV_table by included routing information .

* **How to find optimal route between two hosts?** 

  I consider smallest hops as optimal route. Each host has its own DV_table mapping a subnet to corresponding cost. Taking topology of checkpoint 4 as a example, host ns2 will have two entries in its DV_table first(subnet between ns1 and ns2 and subnet between ns2 and ns3), cost of each is 0. At regular intervals, each host will pack information of DV_table into routing packet and send it to its neighbors. And neighbors can use it to update own DV_table. Finally, each host will find optimal route based DV vector algorithm.

* **How to tolerate failure?**

  Packet loss is not a big deal because of regular retransmission. I set a time limit for each device. If some device doesn't receive routing packet from its neighbor more than this time limit. This host will consider this link unavailable and set cost of corresponding DV_table entry 0xff(means unreachable). all hosts will know this corresponding subnet unreachable or find new optimal route because of subsequent information exchange.

* **How to deal with infinite loops in DV vector algorithm?**

  Two methods to avoid above situation. First, we use reversed poison method. Second, we consider the subnet unreachable When cost == 0xff.



## checkpoint 3

I take 9th packet in checkpoint4/v1.pcapng as a example(how to get this will be explained in checkpoint 4).

<img src="C:\Users\24147\AppData\Roaming\Typora\typora-user-images\image-20211027225531224.png" alt="image-20211027225531224" style="zoom: 80%;" />

Above is forged ICMP packet sent to ns4 from ns1 in checkpoint 4. I will explain the meaning of every bytes one by one.

* First six bytes are mac address of ns2's some network device and subsequent six bytes are mac address of ns1's some network device. So they are `fe:9e:72:ef:be:fb` and `6a:4d:70:1c:01:a4`
* 12th and 13th bytes are 0x08 and 0x00 respectively, which represent upper protocol. Here is IP protocol.
* 14th byte is 0x45, first 4 bits are 0100 representing IPv4 protocol, and latter 4 bit are 0101 representing length of IP header in 4 bytes as a unit. So IP header is 20 bytes length here.
* 15th byte is 0x00 which is used for QoS, 0x00 means this is a ordinary packet.
* 16th and 17th bytes are total packet length including header and payload in a byte, 0x0072 means packet length is 114 bytes.
* 18th and 19th bytes are IP packet id, which used for fragment reassembly to identify if these packets belong to the same packet. Id of this packet is 0x0013.
* 20th and 21th bytes are offset of fragment. 0th bit is reserved, 1th bit identifies if this packet can be fragmented. 2th bit identifies if this packet is last fragment in this packet. And 3th - 15th bits identify offset of fragment in the whole packet. So here 0x00 means this packet can be fragmented and it is a integral packet.
* 22th bytes is rest hops packet can be delivered. Each router will decrease one and it will be discarded when equal to 0. Here is 100(initial value).
* 23th bytes is upper protocol number, here is 0x1 which means ICMP.
* 24th and 25th bytes are checksum to check integrity of IP header. here is 0x3dae.
* 26th, 27th, 28th, 29th are source IP address, here is 0x0a640101, IP address of ns1. 30th, 31th, 32th, 33th are destination IP address, here is 0x0a640302, IP address of ns4.
* Following bytes should be content of ICMP. Because this is forged ICMP packet, I set them all to 0.

## checkpoint 4

After setting up the required topology by using helpers in `vnetUtils`,  I run test/try programs in ns1, sn2, ns3, ns4 respectively.

Here is my configure.

```bash
$./execNS ns1 ip addr
14: v1@if13: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 6a:4d:70:1c:01:a4 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet 10.100.1.1/24 scope global v1
       valid_lft forever preferred_lft forever
    inet6 fe80::684d:70ff:fe1c:1a4/64 scope link 
       valid_lft forever preferred_lft forever
       
$./execNS ns2 ip addr
13: v2@if14: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether fe:9e:72:ef:be:fb brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.100.1.2/24 scope global v2
       valid_lft forever preferred_lft forever
    inet6 fe80::fc9e:72ff:feef:befb/64 scope link 
       valid_lft forever preferred_lft forever
18: v3@if17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 2e:79:a2:cd:7d:67 brd ff:ff:ff:ff:ff:ff link-netnsid 2
    inet 10.100.2.1/24 scope global v3
       valid_lft forever preferred_lft forever
    inet6 fe80::2c79:a2ff:fecd:7d67/64 scope link 
       valid_lft forever preferred_lft forever
       
$./execNS ns3 ip addr
17: v4@if18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 8e:1d:db:20:8c:4a brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.100.2.2/24 scope global v4
       valid_lft forever preferred_lft forever
    inet6 fe80::8c1d:dbff:fe20:8c4a/64 scope link 
       valid_lft forever preferred_lft forever
20: v5@if19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether ba:f7:55:ad:dd:0a brd ff:ff:ff:ff:ff:ff link-netnsid 2
    inet 10.100.3.1/24 scope global v5
       valid_lft forever preferred_lft forever
    inet6 fe80::b8f7:55ff:fead:dd0a/64 scope link 
       valid_lft forever preferred_lft forever

$./execNS ns4 ip addr
19: v6@if20: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether e6:22:4e:06:56:24 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.100.3.2/24 scope global v6
       valid_lft forever preferred_lft forever
    inet6 fe80::e422:4eff:fe06:5624/64 scope link 
       valid_lft forever preferred_lft forever

```

command to run `try` program.

```bash
#need to set LD_LIBRAYR_PATH to load libsrc.so 
$./execNS ns1 ./try 0x0a640101 0x0a640302 1   # first parameter and second parameter are used to specify source IP addr and dstination IP addr.
$./execNS ns2 ./try 0 0     				  # here means ns1 sends packet to ns4. if third parameter is set, this process will send forged ICMP packet based on 
$./execNS ns3 ./try 0 0                       # source IP and destination IP in every two seconds, or we can see this process as a router for forwarding packets.
$./execNS ns4 ./try 0 0
```

 Then, I kill `try` process running in the namespace ns2 around the 50th second and run `try` process again around the 100th second. The following packet capture records are obtained(checkpoint4/v1.pcapng, checkpoint4/v6.pcapng).

<img src="C:\Users\24147\AppData\Roaming\Typora\typora-user-images\image-20211027233712471.png" alt="image-20211027233712471" style="zoom: 80%;" />

Above picture is wireshark running in the namespace ns1 and following picture is wireshark running in the namespace ns4.

<img src="C:\Users\24147\AppData\Roaming\Typora\typora-user-images\image-20211028000540847.png" alt="image-20211028000540847" style="zoom:80%;" />

From v6.pcapng, we can see ns4 receives forged ICMP packet from ns1 normally in the first 50 seconds. After ns2 stops running around the 50th second, ns4 can not receives packets from ns1. And ns1 continues to send ICMP packet until the 80th second(don't receive routing packet from ns2 over 30 seconds, ns1 knows something goes wrong and ns4 is unreachable, so IP layer of ns1 ignores upper level's request of sending packet to ns4). When ns2 runs again around the 100th second, we can see ns1 knows ns4 is reachable again and sends ICMP packet. Meanwhile, ns4 can receive packets from ns1. 



## checkpoint 5

I implement a helper function `printRoutingTable`(src/iplayer.cpp) printing route table to show distance between different namespaces. ns5 and ns6 are added based on topology in checkpoint 4. In detail, there six subnets here.

> 10.100.1.0/24    between ns1(10.100.1.1) and ns2(10.100.1.2)
>
> 10.100.2.0/24    between ns2(10.100.2.1) and ns3(10.100.2.2)
>
> 10.100.3.0/24	 between ns3(10.100.3.1) and ns4(10.100.3.2)
>
> 10.100.4.0/24    between ns2(10.100.4.1) and ns5(10.100.4.2)
>
> 10.100.5.0/24	 between ns3(10.100.5.1) and ns6(10.100.5.2)
>
> 10.100.6.0/24    between ns5(10.100.6.1) and ns6(10.100.6.2)

Then I run the `test/try2` program in ns1, ns2, ns3, ns4, ns5,ns6 respectively.

```bash
$./execNS ns1 ./try2
$./execNS ns2 ./try2
$./execNS ns3 ./try2
$./execNS ns4 ./try2
$./execNS ns5 ./try2
$./execNS ns6 ./try2
```



 `try2` will print route table at the 20th second and print again after 45 second. I kill try2 process running in the ns5 when get route table first time.  The following is output I see in each namespace.

```bash
net id: a.64.2.0 , length of mask: 24, nexthop: a.64.1.2   # route table of ns1 at the 20th second 
net id: a.64.4.0 , length of mask: 24, nexthop: a.64.1.2
net id: a.64.5.0 , length of mask: 24, nexthop: a.64.1.2
net id: a.64.3.0 , length of mask: 24, nexthop: a.64.1.2
net id: a.64.6.0 , length of mask: 24, nexthop: a.64.1.2
net id: a.64.1.0 , length of mask: 24, nexthop: 0.0.0.0
-----------------------------------
net id: a.64.2.0 , length of mask: 24, nexthop: a.64.1.2   # route table of ns1 at the 65th second    
net id: a.64.5.0 , length of mask: 24, nexthop: a.64.1.2
net id: a.64.3.0 , length of mask: 24, nexthop: a.64.1.2
net id: a.64.1.0 , length of mask: 24, nexthop: 0.0.0.0


net id: a.64.6.0 , length of mask: 24, nexthop: a.64.4.2   # route table of ns2 at the 20th second 
net id: a.64.3.0 , length of mask: 24, nexthop: a.64.2.2
net id: a.64.5.0 , length of mask: 24, nexthop: a.64.2.2
net id: a.64.4.0 , length of mask: 24, nexthop: 0.0.0.0
net id: a.64.2.0 , length of mask: 24, nexthop: 0.0.0.0
net id: a.64.1.0 , length of mask: 24, nexthop: 0.0.0.0 
-----------------------------------
net id: a.64.3.0 , length of mask: 24, nexthop: a.64.2.2   # route table of ns2 at the 65th second 
net id: a.64.5.0 , length of mask: 24, nexthop: a.64.2.2
net id: a.64.2.0 , length of mask: 24, nexthop: 0.0.0.0
net id: a.64.1.0 , length of mask: 24, nexthop: 0.0.0.0  


net id: a.64.1.0 , length of mask: 24, nexthop: a.64.2.1    # route table of ns3 at the 20th second 
net id: a.64.4.0 , length of mask: 24, nexthop: a.64.2.1
net id: a.64.6.0 , length of mask: 24, nexthop: a.64.5.2
net id: a.64.5.0 , length of mask: 24, nexthop: 0.0.0.0
net id: a.64.3.0 , length of mask: 24, nexthop: 0.0.0.0
net id: a.64.2.0 , length of mask: 24, nexthop: 0.0.0.0
-----------------------------------
net id: a.64.1.0 , length of mask: 24, nexthop: a.64.2.1     # route table of ns3 at the 65th second 
net id: a.64.5.0 , length of mask: 24, nexthop: 0.0.0.0
net id: a.64.3.0 , length of mask: 24, nexthop: 0.0.0.0
net id: a.64.2.0 , length of mask: 24, nexthop: 0.0.0.0     


net id: a.64.6.0 , length of mask: 24, nexthop: a.64.3.1    # route table of ns4 at the 20th second 
net id: a.64.4.0 , length of mask: 24, nexthop: a.64.3.1
net id: a.64.1.0 , length of mask: 24, nexthop: a.64.3.1
net id: a.64.2.0 , length of mask: 24, nexthop: a.64.3.1
net id: a.64.5.0 , length of mask: 24, nexthop: a.64.3.1
net id: a.64.3.0 , length of mask: 24, nexthop: 0.0.0.0
-----------------------------------
net id: a.64.1.0 , length of mask: 24, nexthop: a.64.3.1    # route table of ns4 at the 65th second
net id: a.64.2.0 , length of mask: 24, nexthop: a.64.3.1
net id: a.64.5.0 , length of mask: 24, nexthop: a.64.3.1
net id: a.64.3.0 , length of mask: 24, nexthop: 0.0.0.0


net id: a.64.1.0 , length of mask: 24, nexthop: a.64.4.1    # route table of ns5 at the 20th second 
net id: a.64.2.0 , length of mask: 24, nexthop: a.64.4.1
net id: a.64.5.0 , length of mask: 24, nexthop: a.64.6.2
net id: a.64.3.0 , length of mask: 24, nexthop: a.64.4.1
net id: a.64.6.0 , length of mask: 24, nexthop: 0.0.0.0
net id: a.64.4.0 , length of mask: 24, nexthop: 0.0.0.0
-----------------------------------


net id: a.64.1.0 , length of mask: 24, nexthop: a.64.5.1    # route table of ns6 at the 20th second 
net id: a.64.4.0 , length of mask: 24, nexthop: a.64.6.1
net id: a.64.2.0 , length of mask: 24, nexthop: a.64.5.1
net id: a.64.3.0 , length of mask: 24, nexthop: a.64.5.1
net id: a.64.6.0 , length of mask: 24, nexthop: 0.0.0.0
net id: a.64.5.0 , length of mask: 24, nexthop: 0.0.0.0
-----------------------------------
net id: a.64.1.0 , length of mask: 24, nexthop: a.64.5.1   # route table of ns6 at the 65th second
net id: a.64.2.0 , length of mask: 24, nexthop: a.64.5.1
net id: a.64.3.0 , length of mask: 24, nexthop: a.64.5.1
net id: a.64.5.0 , length of mask: 24, nexthop: 0.0.0.0
```

Here `nexthop = 0.0.0.0` means some net device of host is in the subnet corresponding to net id. So there is no need to forward the packet to next hop.

For example, let's find the route between ns1(10.100.1.1) to ns6(10.100.5.2 or 10.100.6.2). If we set destination IP address is 10.100.5.2, First in ns1, lookup in route table, next hop is a.64.1.2(ns2), so the packet will be sent to ns2 first. Then, lookup in the ns2's route table, next hop is a.64.2.2(ns3). Finally, next hop equal to 0.0.0.0 in ns3's route table means ns3 know destination is in the same subnet. So ns3 will deliver the packet to 10.100.5.2 directly. We see the distance is 3 between ns1 and ns6.

Above procedure applies to all nodes combination. We will get the following data(at the 20th second):

> distance of (ns1, ns2) or (ns2, ns1) :  1
>
> distance of (ns1, ns3) or (ns3, ns1) :  2
>
> distance of (ns1, ns4) or (ns4, ns1) :  3
>
> distance of (ns1, ns5) or (ns5, ns1) :  2
>
> distance of (ns1, ns6) or (ns6, ns1) :  3
>
> distance of (ns2, ns3) or (ns3, ns2) :  1
>
> distance of (ns2, ns4) or (ns4, ns2) :  2
>
> distance of (ns2, ns5) or (ns5, ns2) :  1
>
> distance of (ns2, ns6) or (ns6, ns2) :  2
>
> distance of (ns3, ns4) or (ns4, ns3) :  1
>
> distance of (ns3, ns5) or (ns5, ns3) :  2
>
> distance of (ns3, ns6) or (ns6, ns3) :  1
>
> distance of (ns4, ns5) or (ns5, ns4) :  3
>
> distance of (ns4, ns6) or (ns6, ns4) :  2
>
> distance of (ns5, ns6) or (ns6, ns5) :  1

After disconnecting ns5 at the 20th second, all other nodes will know subnets of ns5 become unreachable. So only four entries are remained at the 65th second. Repeating previous procedure. We will get the following data(at the 65th second):

>distance of (ns1, ns2) or (ns2, ns1) :  1
>
>distance of (ns1, ns3) or (ns3, ns1) :  2
>
>distance of (ns1, ns4) or (ns4, ns1) :  3
>
>distance of (ns1, ns6) or (ns6, ns1) :  3
>
>distance of (ns2, ns3) or (ns3, ns2) :  1
>
>distance of (ns2, ns4) or (ns4, ns2) :  2
>
>distance of (ns2, ns6) or (ns6, ns2) :  2
>
>distance of (ns3, ns4) or (ns4, ns3) :  1
>
>distance of (ns3, ns6) or (ns6, ns3) :  1
>
>distance of (ns4, ns6) or (ns6, ns4) :  2

## checkpoint 6

First, I implement following function to set routing table manually(src/iplayer.hpp).

```c
void setRoutingTable(int mask_len, uint addr, uint nexthop);  // mask_len is length of mask, addr is network id, and nexthop is IP address of next hop
```

And I insert two fake route table entries in test/try3 program. like following 

```c
setRoutingTable(26, 0x0a6402c0, 0x01010101);   // 0x01010101 is a fake IP address
setRoutingTable(22, 0x0a640000, 0x01010101);
```

Try3 program will receive two command line parameters, representing the source address and destination address respectively, and send forged ICMP packet to destination and print route table in every two seconds.

Net namespace configure is based on topology in checkpoint 4, but delete ns4.  I run try3 program using instruction like the following command(of course, I also need to run `try` program in ns2 and ns3 as routers).

```bash
$./execNS ns1 try3 0x0a640101 0x0a640202
$./execNS ns2 try 0 0
$./execNS ns3 try 0 0
```

See configure in checkpoint4, we will know 0x0a640101 and 0x0a640202 is IP address of ns1 and ns3 respectively. So ns1 will send forged packet to ns3 through ns2(IP address 0x0a640102). 

The following picture is screenshot when running try3 process in namespace ns1. We can see two forged route table entries is inserted into route table.

![image-20211028204352413](C:\Users\24147\AppData\Roaming\Typora\typora-user-images\image-20211028204352413.png)

compared to right entry `24, 0x0a640200, a.64.1.2`  entry `26, 0x0a6402c0, 0x01010101` is more specific but does not match net id of n3 and entry `22, 0x0a640000, 0x01010101` matches net id of ns3 but less specific. So if my implementation is correct, ns1 will send packet to next hop a.64.1.2 and ns3 will receive forged ICMP packet. 

The following picture is from wireshark running in the ns3(`checkpoint6/v4.pcapng`), we can see ns3 receives forged ICMP packet correctly, which shows my implementation is correct.

<img src="C:\Users\24147\AppData\Roaming\Typora\typora-user-images\image-20211028211341431.png" alt="image-20211028211341431" style="zoom:80%;" />



