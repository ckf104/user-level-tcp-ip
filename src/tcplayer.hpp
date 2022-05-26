#ifndef __TCP_HPP
#define __TCP_HPP

#include "general.hpp"
#include <iostream>
#include <queue>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <map>
#include <set>
#include <condition_variable>
#include <random>
#include <linux/tcp.h>
#include <deque>
#include <memory>

#ifdef MEMORY
extern int tcp_socket_create, tcp_socket_delete;
extern print_resource();
#endif

struct tcp_packet;

using std::condition_variable_any;
using std::deque;
using std::map;
using std::queue;
using tcp_packet_ptr = std::unique_ptr<tcp_packet, decltype(&free)>;
using std::shared_ptr;

extern mt19937 init_seq_engine;
extern mutex engine_mtx;
struct tcp_timer;

using tcp_timer_ptr = std::unique_ptr<tcp_timer>;
extern std::multiset<tcp_timer_ptr> timer_tree;

enum class tcp_status
{
    CLOSED, // no closing for simultaneous close
    LISTEN,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    TIME_WAIT,
    CLOSE_WAIT,
    LAST_ACK,
    OTHER_ABORT, // no responds of other side over a long time, wait to be closed by user
    NO_USE,      // channel has been closed on both sides, wait closed by user
    ORPHAN,      // has been closed by user, can delete from sockmap directly
};

struct tcp_packet;

class tcp_socket
{
public:
    shared_mutex rw_mtx;
    condition_variable_any cond_connect;
    condition_variable_any cond_accept;
    condition_variable_any cond_send;
    condition_variable_any cond_recv;
#ifdef block_close
    condition_variable_any cond_close;
#endif
    //decltype(timer_tree.begin()) clock;
    tcp_timer *clock;

    uint src_ipaddr, dst_ipaddr; // managed by sockmap_mtx
    uint16_t src_port, dst_port;
    tcp_status status;
    uint closed;      // the socket closed by user ?
    uint send_closed; // my write channel closed ? -> shutdown(write)
    uint rcv_closed;  // write channel of other side closed ? -> received fin
    // send_closed = 1 not necessarily means change of status, until all data have been sent, ditto for rcv_closed

    queue<uint> accept_queue; // only for listen socket
    int backlog;
    uint mother_fd; // fd of listen socket

    char *send_buf, *rev_buf;          // buffer size is 65536 - 1 in fact.
    uint sd_data_end;                  // mod buf_size,  buf[data_end % buf_size] is invalid data.
    uint rev_data_start, rev_data_end; // max node in ooo_data + length = rev_data_end;

    uint resend_time; // consider other side as crashed resend_time = 7
    uint rto;         // retransmission timeout
    uint window_size;
    uint16_t other_mss;
    uint16_t my_mss;

    uint init_seq;      // ack may be lost, so init_seq need to be stored
    uint unack_seq;     // replace sd_data_start
    uint next_send_seq; // unsent data between next_send_seq and sd_data_end

    uint other_init_seq;
    uint next_rev;
    map<uint, uint> ooo_data;

    deque<tcp_packet_ptr> resent_queue;

    tcp_socket();
    ~tcp_socket();
    void get_sdbuf_data(void *dst, uint start, uint leng);
    void get_rcvbuf_data(void *dst, uint start, uint leng);
    void write_sd_buf_data(const void *dst, uint start, uint leng);
    void write_rcvbuf_data(const void *dst, uint start, uint leng);
    void retransmission();

    int rcv_ack_pkt_established(const uint8_t *data, uint pkt_len, shared_ptr<tcp_socket> &myself);
    int rcv_ack_pkt_syn_rcvd(const uint8_t *data, uint pkt_len);
    int rcv_ack_pkt_fin_wait(const uint8_t *data, uint pkt_len, shared_ptr<tcp_socket> &myself);
    int rcv_ack_pkt_close_wait(const tcphdr *hdr, shared_ptr<tcp_socket> &myself);
    int rcv_ack_pkt_last_ack(const tcphdr *hdr, shared_ptr<tcp_socket> &myself);
    int rcv_ack_pkt_time_wait();
    int rcv_rst_pkt();

    int rcv_data(uint seq_number, uint payload_len, const uint8_t *pure_data, uint has_fin = 0);
    int update_unack_seq(uint ack_number, shared_ptr<tcp_socket> &myself);

    enum class send_type
    {
        general,
        necessary,
    };
    int send_tcp_ack_pkt(send_type type, shared_ptr<tcp_socket> &myself); // send a ack, if possible, with some new data

    int send_tcp_fin_pkt(shared_ptr<tcp_socket> &myself);
};

struct tcp_packet
{
    uint data_len; // data_len includes tcp options
    ether_header eth_hdr;
    iphdr ip_hdr;
    tcphdr tcp_hdr;
    char data[];
} __attribute__((packed));

struct mss_option
{
    uint8_t kind;
    uint8_t length;
    uint16_t mss;
};

void get_tcp_syn_hdr(tcp_socket *sock, tcphdr *hdr, int need_ack = 0);

int rcv_tcp_packet(uint src_ipaddr, uint dst_ipaddr, const uint8_t *data, uint16_t tcp_packet_len);

void get_tcp_ack_hdr(tcp_socket *sock, tcphdr *hdr, uint payload_len, uint need_push = 0, uint need_fin = 0);

int rcv_tcp_syn_packet(uint my_ipaddr, uint dst_ipddr, uint16_t my_port, uint16_t dst_port, const tcphdr *hdr);

int rcv_tcp_syn_ack_packet(uint my_ipaddr, uint dst_ipddr, uint16_t my_port, uint16_t dst_port, const tcphdr *hdr);

int rcv_tcp_rst_packet(uint my_ipaddr, uint dst_ipddr, uint16_t my_port, uint16_t dst_port, const tcphdr *hdr);

int rcv_tcp_ack_packet(uint my_ipaddr, uint dst_ipddr, uint16_t my_port, uint16_t dst_port, const uint8_t *data, uint pkt_len);

int send_tcp_rst_pkt(uint src_ipaddr, uint dst_ipaddr, const tcphdr *hdr, uint payload_len);

#endif