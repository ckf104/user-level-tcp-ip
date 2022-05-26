#ifndef __SOCK_HPP
#define __SOCK_HPP

#include "general.hpp"
#include "tcplayer.hpp"
#include <unordered_map>
#include <mutex>
#include <memory>

using std::unordered_map;
using std::mutex;
using tcp_socket_ptr = std::shared_ptr<tcp_socket>;

extern "C" int __wrap_socket(int domain, int type, int protocol);
extern "C" int __wrap_bind(int sockfd, const sockaddr *addr, socklen_t addr_len);
extern "C" int __wrap_listen(int sockfd, int backlog);
extern "C" int __wrap_connect(int sockfd, const sockaddr *addr, socklen_t addr_len);
extern "C" int __wrap_accept(int sockfd, sockaddr *addr, socklen_t* addr_len);
extern "C" int __wrap_read(int sockfd, void* buf, size_t nbyte);
extern "C" int __wrap_write(int sockfd, const void* buf, size_t nbyte);
extern "C" int __wrap_close(int sockfd);
extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void *val, socklen_t leng);

uint add_socket(tcp_socket_ptr ptr);
bool check_port(uint src_addr, uint16_t src_port);
uint16_t choose_port(uint src_addr);

extern unordered_map<uint, tcp_socket_ptr> fd_to_sock;
extern volatile uint now_sockfd;
extern shared_mutex sockmap_mtx;
extern volatile uint16_t hint_port;

#endif