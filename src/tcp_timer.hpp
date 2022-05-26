#ifndef __TCP_TIMER_HPP
#define __TCP_TIMER_HPP

#include "general.hpp"
#include "sock.hpp"
#include <set>

using std::multiset;

struct tcp_timer
{ // here callback func is fixed
    uint base_ticks;
    uint expire_time;
    tcp_socket_ptr ptr;
    
    tcp_timer(uint base, uint t, tcp_socket_ptr& timer_owner);
    ~tcp_timer();
};

using tcp_timer_ptr = std::unique_ptr<tcp_timer>;

bool operator<(const tcp_timer_ptr& timer_1, const tcp_timer_ptr& tiemr_2);
extern multiset<tcp_timer_ptr> timer_tree;
extern mutex tcp_timer_tree_mtx;
extern volatile uint ticks;
extern void clock_manager();
void erase_clock(tcp_socket *ptr);

#ifdef MEMORY
extern int tcp_timer_create, tcp_timer_delete;
#endif

#endif