#include <pcap/pcap.h>
#include "../src/device.hpp"
#include "../src/packetio.hpp"
#include "../src/general.hpp"
#include "../src/arp.hpp"
#include "../src/iplayer.hpp"
#include "../src/sock.hpp"
#include <fcntl.h>
#include <iostream>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <string>
#include "parameter.hpp"

using std::cerr;
using std::cout;
using std::endl;

/*uint8_t dstmac[ETH_ALEN] = {0, 0x50, 0x56, 0xc0, 0, 0x8};
const char saddr[] = "192.168.31.141";
const char daddr[] = "192.168.31.1";
const char deviceName[] = "ens33";*/
/*
TEST(simpleRecevingTest, connectReceiving)
{
    char *buf = (char *)calloc(1, msg_len + 8);
    ASSERT_NE(buf, nullptr);
    //int file = open("tmp", O_WRONLY | O_CREAT | O_TRUNC);

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(fd, -1);

    addrinfo *tmp = nullptr;
    ASSERT_EQ(getaddrinfo("10.100.1.2", STR(listen_port), nullptr, &tmp), 0);
    ASSERT_NE(tmp, nullptr);

    int a = connect(fd, tmp->ai_addr, sizeof(sockaddr_in));
    EXPECT_EQ(a, 0);
    if (a == 0)
    {
        int sum = 0, tmp;
        while ((tmp = read(fd, buf + sum, 4096)) > 0)
            sum += tmp;
        EXPECT_EQ(sum, msg_len + 8);
        std::string u(buf, buf + msg_len);
        std::hash<std::string> hash_func;
        //write(file, buf, msg_len);
        //close(file);
        EXPECT_EQ(hash_func(u), *(uint64_t *)(buf + msg_len));
    }
    else
        cout << a << endl;
    free(buf);
    close(fd);
    freeaddrinfo(tmp);
    std::this_thread::sleep_for(std::chrono::seconds(5));
}*/

TEST(listenWritingTest, listenTest)
{
    mt19937 engine;
    engine.seed(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    std::uniform_int_distribution<> generaotor(-127, 127);
    std::string tmp_s;
    tmp_s.reserve(msg_len);
    uint64_t hash_value;
    for (int i = 0; i < msg_len; ++i)
    {
        tmp_s += char(generaotor(engine));
        //tmp_s += (i % 50) == 0 ? '\n' : '1';
    }
    std::hash<std::string> hash_func;
    hash_value = hash_func(tmp_s);

    char *buf = (char *)calloc(1, msg_len + 8);
    ASSERT_NE(buf, nullptr);
    //int file = open("tmp", O_WRONLY | O_CREAT | O_TRUNC);

    addrinfo *tmp = nullptr;
    ASSERT_EQ(getaddrinfo("0.0.0.0", STR(listen_port), nullptr, &tmp), 0);
    ASSERT_NE(tmp, nullptr);

    int fd = socket(tmp->ai_family, tmp->ai_socktype, tmp->ai_protocol);
    ASSERT_NE(fd, -1);
    ASSERT_EQ(bind(fd, tmp->ai_addr, sizeof(sockaddr_in)), 0);
    ASSERT_EQ(listen(fd, 30), 0);

    sockaddr_in other;
    socklen_t leng;
    int acc_fd = accept(fd, (sockaddr *)&other, &leng);
    ASSERT_NE(acc_fd, -1);
    ASSERT_EQ(leng, sizeof(sockaddr_in));

    const char *t = tmp_s.c_str();
    int sum = 0, sum_r = 0;
    while (sum < msg_len || sum_r < msg_len)
    {
        if (sum < msg_len)
        {
            int rel = write(acc_fd, t + sum, std::min(1024, msg_len - sum));
            if (rel <= 0)
                break;
            sum += rel;
        }
        if (sum_r < msg_len)
        {
            int rel = read(acc_fd, buf + sum_r, std::min(4096, msg_len - sum_r));
            if (rel <= 0)
                break;
            sum_r += rel;
        }
    }
    write(acc_fd, &hash_value, sizeof(uint64_t));
    EXPECT_EQ(sum, msg_len);
    EXPECT_EQ(sum_r, msg_len);
    uint64_t rcv_hash = 0;
    read(acc_fd, &rcv_hash, sizeof(uint64_t));
    EXPECT_EQ(hash_func(std::string{buf, buf + sum_r}), rcv_hash);

    close(fd);
    close(acc_fd);
    free(buf);
    std::this_thread::sleep_for(std::chrono::seconds(10));
}

int main(int argc, char *argv[]) // argv[1] -> saddr, argv[2] -> daddr, argv[3] -> send pkt
{
    close_routing_func();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
    //sendArp(0xc0a81f01, 0);
    //cout << "ret: " << ret << endl;
}
