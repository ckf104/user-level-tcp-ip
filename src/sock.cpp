#include "sock.hpp"
#include "iplayer.hpp"
#include "device.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <thread>
#include <chrono>

volatile uint now_sockfd = init_sock_fd;
volatile uint16_t hint_port = low_port;

unordered_map<uint, tcp_socket_ptr> fd_to_sock __attribute__((init_priority(200)));
shared_mutex sockmap_mtx __attribute__((init_priority(201)));

uint add_socket(tcp_socket_ptr ptr)
{ // need to have unique sockmap_mtx
    uint tmp = now_sockfd - 1;
    while (1)
    {
        uint ret = now_sockfd++;
        if (fd_to_sock.count(ret) == 0)
        {
            fd_to_sock.emplace(ret, ptr);
            return ret;
        }
        if (ret == tmp)
        {
            return -1;
        }
    }
}

int __wrap_socket(int domain, int type, int protocol)
{
    if (domain != AF_INET || type != SOCK_STREAM)
    {
        return -1;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP)
    {
        return -1;
    }
    unique_lock lock(sockmap_mtx);
    return add_socket(tcp_socket_ptr{new tcp_socket{}});
}

int __wrap_bind(int sockfd, const sockaddr *addr, socklen_t addr_len)
{
    sockaddr_in *address = (sockaddr_in *)addr;
    uint little_ipaddr = little2big<uint>(address->sin_addr.s_addr);
    uint16_t little_port = little2big<uint16_t>(address->sin_port);

    if (addr_len != sizeof(sockaddr_in) || addr->sa_family != AF_INET) // check protocol
    {
        return -1;
    }
    if (little_ipaddr == 0)
    {
        goto good;
    }
    for (int i = 0; i < maxDeviceNum; ++i)
    { // check ip address
        unique_lock device_lock(device_mtx[i]);
        if (deviceTable[i] && deviceTable[i]->ipaddr == little_ipaddr)
        {
            goto good; // jumping out of scope using goto is safe
        }
    }
    return -1;

good:
    unique_lock lock(sockmap_mtx);
    if (fd_to_sock.count(sockfd) != 1)
    { // check if valid sockfd and valid status
        return -1;
    }
    shared_lock socket_lock(fd_to_sock[sockfd]->rw_mtx);
    if (fd_to_sock[sockfd]->status != tcp_status::CLOSED)
    {
        return -1;
    }
    socket_lock.unlock();
    // once we determine status of sockfd is closed, methods that change of status are connect, listen,
    // any of which need to acquire sockmap_mtx, so releasing rw_mtx now is safe.

    if (little_port != 0) // port number chosen by user
    {
        if (check_port(little_ipaddr, little_port))
        {
            fd_to_sock[sockfd]->src_ipaddr = little_ipaddr;
            fd_to_sock[sockfd]->src_port = little_port;
            return 0;
        }
        return -1;
    }

    uint16_t rel_port = choose_port(little_ipaddr);
    if (rel_port != 0)
    {
        fd_to_sock[sockfd]->src_ipaddr = little_ipaddr;
        fd_to_sock[sockfd]->src_port = rel_port;
        return 0;
    }
    return -1;
}

int __wrap_listen(int sockfd, int backlog)
{
    if (backlog <= 0) // backlog > 0
    {
        return -1;
    }
    tcp_socket_ptr ptr;
    shared_lock lock(sockmap_mtx);
    if (fd_to_sock.count(sockfd) != 1 || fd_to_sock[sockfd]->src_ipaddr == broad_ipaddr)
    { // valid sockfd ? valid status ? has called bind() ?
        return -1;
    }
    else
    {
        ptr = fd_to_sock[sockfd];
        ptr->rw_mtx.lock(); // need to acquire rw_mtx then release sockmap_mtx, order is important.
        lock.unlock();      // but reversed order here is ok ?
    }
    if (ptr->status != tcp_status::CLOSED)
    {
        ptr->rw_mtx.unlock();
        return -1;
    }
    ptr->backlog = backlog;
    ptr->status = tcp_status::LISTEN;
    ptr->rw_mtx.unlock();
    return 0;
}

int __wrap_connect(int sockfd, const sockaddr *addr, socklen_t addr_len)
{
    sockaddr_in *dst_addr = (sockaddr_in *)addr;
    uint little_dstip = little2big<uint>(dst_addr->sin_addr.s_addr);
    uint16_t little_dstport = little2big<uint16_t>(dst_addr->sin_port);
    if (dst_addr->sin_family != AF_INET || addr_len != sizeof(sockaddr_in))
    {
        return -1;
    }

    device_share_ptr copy;
    for (int i = 0; i <= 5; ++i)
    {
        if (lmp_find(little_dstip, NULL, copy) != 0)
        { // check if destination is reacheable
            std::this_thread::sleep_for(std::chrono::seconds(1 << i));
        }
        else
            goto find;
    }
    return -1;
find:
    tcp_socket_ptr ptr;
    unique_lock lock(sockmap_mtx);
    if (fd_to_sock.count(sockfd) != 1)
    {
        return -1;
    }
    else
    {
        ptr = fd_to_sock[sockfd];
    }
    unique_lock socket_lock(ptr->rw_mtx);
    if (ptr->status != tcp_status::CLOSED)
    {
        return -1;
    }
    if (ptr->src_port == 0 && (ptr->src_port = choose_port(copy->ipaddr)) == 0)
    {
        return -1;
    }
    if (ptr->src_ipaddr == broad_ipaddr || ptr->src_ipaddr == 0)
    { // not call bind() before call connect(), need to choose src_ip and src port first
        ptr->src_ipaddr = copy->ipaddr;
    }
    lock.unlock();
    ptr->dst_ipaddr = little_dstip;
    ptr->dst_port = little_dstport;
    ptr->status = tcp_status::SYN_SENT;

    engine_mtx.lock();
    ptr->init_seq = init_seq_engine();
    engine_mtx.unlock();

    ptr->next_send_seq = ptr->init_seq + 1; // length of syn packet is 1
    ptr->sd_data_end = ptr->init_seq + 1;
    ptr->unack_seq = ptr->init_seq;

    uint8_t *tcp_syn_pkt = (uint8_t *)calloc(1, sizeof(ether_header) + sizeof(iphdr) + sizeof(tcphdr) + 4);
    get_tcp_syn_hdr(ptr.get(), (tcphdr *)(tcp_syn_pkt + sizeof(ether_header) + sizeof(iphdr)));

    int i = 0;
    while (i < 7)
    {
        sendipPkt(ptr->src_ipaddr, tcpType, tcp_syn_pkt, sizeof(tcphdr) + 4, ptr->dst_ipaddr);
        //printf("connect %d times\n", i);
        std::cv_status cv_rel = ptr->cond_connect.wait_for(socket_lock, std::chrono::seconds(1 << i));
        if (cv_rel == std::cv_status::no_timeout)
        {                                                                                 // notified by other threads, if status is not changed, a RST received, otherwise connection established
            free(tcp_syn_pkt);                                                            // thread that receiving RST don't change status into closed to avoid activating
            if (ptr->status == tcp_status::SYN_SENT || ptr->status == tcp_status::ORPHAN) // subsequent bind(), connect() function.
            {
                ptr->status = ptr->closed ? tcp_status::ORPHAN : tcp_status::CLOSED;
                return -1;
            }
            return 0;
        }
        ++i;
    }
    if (ptr->status == tcp_status::SYN_SENT || ptr->status == tcp_status::CLOSED || ptr->status == tcp_status::ORPHAN)
    {
        ptr->status = ptr->closed ? tcp_status::ORPHAN : tcp_status::CLOSED; // it's possible for ptr->status = closed ?
        free(tcp_syn_pkt);
        return -1;
    }
    return 0;
}

int __wrap_accept(int sockfd, sockaddr *addr, socklen_t *addr_len)
{
    sockaddr_in *other_addr = (sockaddr_in *)addr;
    memset(other_addr->sin_zero, 0, sizeof(other_addr->sin_zero));
    shared_lock lock(sockmap_mtx);
    if (fd_to_sock.count(sockfd) == 0)
    {
        return -1;
    }
    auto ptr = fd_to_sock[sockfd];
    unique_lock socket_lock(ptr->rw_mtx);
    if (ptr->status != tcp_status::LISTEN)
    {
        return -1;
    }
    lock.unlock();

    uint retfd = 0;
    if (!ptr->accept_queue.empty())
    {
        retfd = ptr->accept_queue.front();
        ptr->accept_queue.pop();
        socket_lock.unlock();

        tcp_socket_ptr &p = fd_to_sock.at(retfd); // assert
        other_addr->sin_family = AF_INET;
        other_addr->sin_port = little2big(p->dst_port);
        other_addr->sin_addr.s_addr = little2big(p->dst_ipaddr);
        *addr_len = sizeof(sockaddr_in);

        return retfd;
    }
    else
    {
        ptr->cond_accept.wait(socket_lock, [ptr]() -> bool
                              { return !ptr->accept_queue.empty() || ptr->status != tcp_status::LISTEN; });
        if (ptr->status != tcp_status::LISTEN)
        {
            assert(ptr->status == tcp_status::ORPHAN);
            return -1;
        }
        else
        {
            retfd = ptr->accept_queue.front(); // no guarantee that status of retfd is established
            ptr->accept_queue.pop();           // e.g., other side has close his scoket, so status of retfd is close_wait
            socket_lock.unlock();

            tcp_socket_ptr &p = fd_to_sock.at(retfd); // assert
            other_addr->sin_family = AF_INET;
            other_addr->sin_port = little2big(p->dst_port);
            other_addr->sin_addr.s_addr = little2big(p->dst_ipaddr);
            *addr_len = sizeof(sockaddr_in);
            return retfd;
        }
    }
}

// following function need to check if socket has been closed
// above function don't have to, because status of closed socket can't be closed or listen
int __wrap_read(int sockfd, void *buf, size_t nbyte)
{
    if (sockfd < init_sock_fd) // error occurs if sockfd wrapping ?
    {
        return read(sockfd, buf, nbyte);
    }

    shared_lock lock(sockmap_mtx);
    if (fd_to_sock.count(sockfd) == 0)
    {
        return -1;
    }
    tcp_socket_ptr ptr = fd_to_sock[sockfd];
    unique_lock socket_lock(ptr->rw_mtx);
    lock.unlock();
    if (ptr->closed)
    {
        return -1;
    }

    switch (ptr->status)
    {
    case tcp_status::ESTABLISHED:
    case tcp_status::FIN_WAIT_1:
    case tcp_status::FIN_WAIT_2:
    case tcp_status::TIME_WAIT:
    case tcp_status::CLOSE_WAIT:
    case tcp_status::LAST_ACK:
    case tcp_status::OTHER_ABORT:
    case tcp_status::NO_USE:
        goto good;
    default:
        return -1;
    }

good:
    uint rel_byte = 0;
    ptr->cond_recv.wait_for(socket_lock, std::chrono::seconds(rw_timeout), [&ptr]() -> bool
                            {
                                uint delta = ptr->next_rev == ptr->rev_data_end && ptr->rcv_closed;
                                if (ptr->rev_data_start != ptr->next_rev - delta) // return 1 means have available data
                                {                                                 // or not possible to get new data.
                                    return 1;                                     // consider length of fin flag
                                }
                                switch (ptr->status)
                                {
                                case tcp_status::CLOSE_WAIT:
                                case tcp_status::LAST_ACK:
                                case tcp_status::TIME_WAIT:
                                    assert(ptr->next_rev == ptr->rev_data_end);
                                case tcp_status::NO_USE:
                                case tcp_status::OTHER_ABORT:
                                case tcp_status::ORPHAN:
                                    return 1;
                                default:
                                    return 0;
                                }
                            });
    uint delta = ptr->next_rev == ptr->rev_data_end && ptr->rcv_closed;
    if (ptr->next_rev - delta != ptr->rev_data_start)
    {
        rel_byte = std::min((uint)nbyte, ptr->next_rev - ptr->rev_data_start - delta);
        ptr->get_rcvbuf_data(buf, ptr->rev_data_start, rel_byte);
        ptr->rev_data_start += rel_byte;
        return rel_byte;
    }
    switch (ptr->status)
    {
    case tcp_status::ESTABLISHED:
    case tcp_status::FIN_WAIT_1:
    case tcp_status::FIN_WAIT_2: // may get new data in the future
        return 0; // return -1;
    case tcp_status::CLOSE_WAIT:
    case tcp_status::LAST_ACK:
    case tcp_status::TIME_WAIT:
    case tcp_status::NO_USE:
    case tcp_status::OTHER_ABORT:
    case tcp_status::ORPHAN: // another thread closes this socket ?
        return 0;
    default:
        assert(false);
    }
}

int __wrap_write(int sockfd, const void *buf, size_t nbyte)
{
    if (sockfd < init_sock_fd)
    {
        return write(sockfd, buf, nbyte);
    }

    shared_lock lock(sockmap_mtx);
    if (fd_to_sock.count(sockfd) == 0)
    {
        return -1;
    }
    tcp_socket_ptr ptr = fd_to_sock[sockfd];
    unique_lock socket_lock(ptr->rw_mtx);
    lock.unlock();
    if (ptr->closed || ptr->send_closed)
    {
        return -1;
    }

    switch (ptr->status)
    {
    case tcp_status::ESTABLISHED:
    case tcp_status::CLOSE_WAIT:
        goto good;
    default:
        return -1;
    }

good:
    ptr->cond_send.wait_for(socket_lock, std::chrono::seconds(rw_timeout), [&ptr]() -> bool
                            {
                                if (ptr->sd_data_end - ptr->unack_seq < tcp_buffer_len - 1)
                                {
                                    return 1;
                                }
                                switch (ptr->status)
                                {
                                case tcp_status::ESTABLISHED:
                                case tcp_status::CLOSE_WAIT:
                                    return 0;
                                default:
                                    return 1;
                                }
                            });
    if (ptr->status == tcp_status::ESTABLISHED || ptr->status == tcp_status::CLOSE_WAIT)
    {
        if (ptr->sd_data_end - ptr->unack_seq < tcp_buffer_len - 1)
        {
            uint rel_byte = std::min((uint)nbyte, tcp_buffer_len - 1 - (ptr->sd_data_end - ptr->unack_seq));
            ptr->write_sd_buf_data(buf, ptr->sd_data_end, rel_byte);
            ptr->sd_data_end += rel_byte;
            ptr->send_tcp_ack_pkt(tcp_socket::send_type::general, ptr);
            return rel_byte;
        }
        return -1; // timeout
    }
    return 0;
}

int __wrap_close(int sockfd)
{
    if (sockfd < init_sock_fd)
        return close(sockfd);

    shared_lock lock(sockmap_mtx);
    if (fd_to_sock.count(sockfd) == 0)
        return -1;
    tcp_socket_ptr ptr = fd_to_sock[sockfd];
    unique_lock socket_lock(ptr->rw_mtx);
    lock.unlock();
    if (ptr->closed)
        return -1;

    switch (ptr->status)
    {
    case tcp_status::LISTEN: // first close established but not accepted socket
        while (!ptr->accept_queue.empty())
        {
            __wrap_close(ptr->accept_queue.front());
            ptr->accept_queue.pop();
        }
        ptr->cond_accept.notify_all(); // some threads may be blocked because of empty accept_queue
    case tcp_status::CLOSED:
    case tcp_status::NO_USE:
    case tcp_status::OTHER_ABORT:
        assert(!ptr->clock);
        ptr->status = tcp_status::ORPHAN;
        break;
    case tcp_status::ESTABLISHED:
    case tcp_status::CLOSE_WAIT:
        ptr->send_closed = 1;
        ptr->send_tcp_fin_pkt(ptr);
#ifdef block_close
        ptr->cond_close.wait_for(socket_lock, std::chrono::seconds(rw_timeout), [&ptr]()
                                 {
                                     switch (ptr->status)
                                     {
                                     case tcp_status::FIN_WAIT_2:
                                     case tcp_status::TIME_WAIT:
                                     case tcp_status::NO_USE:
                                     case tcp_status::OTHER_ABORT:
                                     case tcp_status::ORPHAN:
                                         return 1;
                                     default:
                                         return 0;
                                     }
                                 });
#endif
        break;
    case tcp_status::SYN_SENT:
        ptr->send_closed = 1;
        ptr->cond_connect.notify_one(); // closed by other threads
        ptr->status = tcp_status::ORPHAN;
        //ptr->send_tcp_rst_pkt();
        break;
    case tcp_status::FIN_WAIT_1:
    case tcp_status::FIN_WAIT_2:
    case tcp_status::TIME_WAIT:
    case tcp_status::LAST_ACK:
        assert(ptr->send_closed == 1);
        break;
    default:
        assert(false);
    }
    ptr->closed = 1;
    ptr->cond_recv.notify_all(); // may become unblocked because of status change
    ptr->cond_send.notify_all();
    return 0;
}

int __wrap_setsockopt(int sockfd, int level, int optname, const void *val, socklen_t leng)
{
    return 0;
}

bool check_port(uint src_addr, uint16_t src_port)
{ // caller has share lock of sockmap_mtx
    for (auto p : fd_to_sock)
    { // check if have same endpoint
        //shared_lock lock(p.second->rw_mtx);  no effect
        if (p.second->src_port == src_port && (p.second->src_ipaddr == src_addr || p.second->src_ipaddr == 0 || src_addr == 0))
        {
            return false;
        }
    }
    return true;
}

uint16_t choose_port(uint src_addr)
{ // caller has unique lock of sockmap_mtx
    uint16_t tmp = hint_port;
    while (1)
    {
        hint_port = hint_port + 1 > high_port ? low_port : hint_port + 1;
        if (hint_port == tmp)
        {
            return 0;
        }
        if (check_port(src_addr, hint_port))
        {
            return hint_port;
        }
    }
}