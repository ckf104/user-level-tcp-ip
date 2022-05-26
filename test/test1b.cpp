#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <chrono>
#include <random>
#include <algorithm>
#include <gtest/gtest.h>
#include <netdb.h>
#include "parameter.hpp"
using namespace std;

#define BACKLOG 5
/*
TEST(sendTest, sdTest)
{
  mt19937 engine;
  engine.seed(chrono::system_clock::to_time_t(chrono::system_clock::now()));
  uniform_int_distribution<> generaotor(-127, 127);
  string tmp_s;
  tmp_s.reserve(msg_len);
  uint64_t hash_value;
  for (int i = 0; i < msg_len; ++i)
  {
    tmp_s += char(generaotor(engine));
    //tmp_s += (i % 50) == 0 ? '\n' : '1';
  }
  hash<string> hash_func;
  hash_value = hash_func(tmp_s);

  int sockfd, new_fd;
  struct sockaddr_in my_addr;
  struct sockaddr_in their_addr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0); //建立socket
  ASSERT_NE(sockfd, -1);

  int on = 1;
  ASSERT_EQ(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)), 0);

  my_addr.sin_family = AF_INET;
  my_addr.sin_port = htons(listen_port);
  my_addr.sin_addr.s_addr = 0;
  bzero(&(my_addr.sin_zero), 8);
  ASSERT_EQ(bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)), 0);

  ASSERT_EQ(listen(sockfd, BACKLOG), 0);

  socklen_t sin_size = sizeof(struct sockaddr_in);
  new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
  ASSERT_NE(new_fd, -1);

  const char *t = tmp_s.c_str();
  int sum = 0;
  while (sum < msg_len)
  {
    int rel = send(new_fd, t + sum, min(1024, msg_len - sum), 0);
    EXPECT_GT(rel, 0);
    sum += rel;
  }
  send(new_fd, &hash_value, sizeof(uint64_t), 0);
  
  EXPECT_EQ(sum, msg_len);
  close(new_fd);
  close(sockfd);
  
  this_thread::sleep_for(chrono::seconds(5));
}*/

TEST(simpleRecevingTest, connectReceiving)
{
  mt19937 engine;
  engine.seed(chrono::system_clock::to_time_t(chrono::system_clock::now()));
  uniform_int_distribution<> generaotor(-127, 127);
  string tmp_s;
  tmp_s.reserve(msg_len);
  uint64_t hash_value;
  for (int i = 0; i < msg_len; ++i)
  {
    tmp_s += char(generaotor(engine));
    //tmp_s += (i % 50) == 0 ? '\n' : '1';
  }
  hash<string> hash_func;
  hash_value = hash_func(tmp_s);

  char *buf = (char *)calloc(1, msg_len + 8);
  ASSERT_NE(buf, nullptr);
  //int file = open("tmp", O_WRONLY | O_CREAT | O_TRUNC);

  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  ASSERT_NE(fd, -1);

  addrinfo *tmp = nullptr;
  ASSERT_EQ(getaddrinfo("10.100.1.1", STR(listen_port), nullptr, &tmp), 0);
  ASSERT_NE(tmp, nullptr);

  int a = connect(fd, tmp->ai_addr, sizeof(sockaddr_in));
  ASSERT_EQ(a, 0);

  const char *t = tmp_s.c_str();
  int sum = 0, sum_r = 0;
  while (sum < msg_len || sum_r < msg_len)
  {
    if (sum < msg_len)
    {
      int rel = write(fd, t + sum, std::min(1024, msg_len - sum));
      if (rel <= 0)
        perror("wirte: ");
      sum += rel;
    }
    if (sum_r < msg_len)
    {
      int rel = read(fd, buf + sum_r, std::min(4096, msg_len - sum_r));
      if (rel <= 0)
        perror("read : ");
      sum_r += rel;
    }
  }
  write(fd, &hash_value, sizeof(uint64_t));
  EXPECT_EQ(sum, msg_len);
  EXPECT_EQ(sum_r, msg_len);
  uint64_t rcv_hash = 0;
  read(fd, &rcv_hash, sizeof(uint64_t));
  EXPECT_EQ(hash_func(std::string{buf, buf + sum_r}), rcv_hash);

  std::this_thread::sleep_for(std::chrono::seconds(10)); 
  free(buf);
  close(fd);
  freeaddrinfo(tmp);
  std::this_thread::sleep_for(std::chrono::seconds(1));
}

int main(int argc, char *argv[])
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
