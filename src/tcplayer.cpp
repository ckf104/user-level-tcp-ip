#include "tcplayer.hpp"
#include "general.hpp"
#include "sock.hpp"
#include "iplayer.hpp"
#include "tcp_timer.hpp"

#ifdef MEMORY
int tcp_socket_create = 0, tcp_timer_delete = 0;
#endif

mt19937 init_seq_engine __attribute__((init_priority(250)));
mutex engine_mtx __attribute__((init_priority(251)));

tcp_socket::tcp_socket()
{
    next_rev = 0;
    backlog = 0;
    status = tcp_status::CLOSED;
    closed = 0;
    send_closed = 0;
    rcv_closed = 0;
    send_buf = rev_buf = NULL;
    rto = default_rto;
    my_mss = default_mss;
    other_mss = 0;

    src_ipaddr = broad_ipaddr; // which means no src_ipaddr
    src_port = 0;
    dst_ipaddr = broad_ipaddr;
    dst_port = 0;

    clock = NULL;
#ifdef MEMORY
    cout << "tcp_socket created" << endl;
    __sync_fetch_and_add(&tcp_socket_create, 1);
#endif
}

tcp_socket::~tcp_socket()
{
    if (send_buf)
        free(send_buf);
    if (rev_buf)
        free(rev_buf);
#ifdef MEMORY
    cout << "tcp_socket deleted" << endl;
    __sync_fetch_and_add(&tcp_socket_delete, 1);
#endif
}

// called by clock manager, now have tcp_timer_tree_mtx and shared rw_mtx
// as a nop operation if resent_queue is empty
void tcp_socket::retransmission()
{
    for (tcp_packet_ptr &resent_pkt : resent_queue)
    {
        resent_pkt->tcp_hdr.ack_seq = little2big(next_rev);
        resent_pkt->tcp_hdr.window = little2big<uint16_t>(tcp_buffer_len - 1 - (next_rev - rev_data_start));
        resent_pkt->tcp_hdr.check = 0;
        uint16_t total_pkt_len = resent_pkt->data_len + sizeof(tcphdr);
        uint base = little2big<uint16_t>(src_ipaddr & 0xffff) + little2big<uint16_t>(src_ipaddr >> 16) +
                    little2big<uint16_t>(dst_ipaddr & 0xffff) + little2big<uint16_t>(dst_ipaddr >> 16) +
                    (tcpType << 8) + little2big<uint16_t>(total_pkt_len);
        resent_pkt->tcp_hdr.check = getChecksum((const uint16_t *)&resent_pkt->tcp_hdr,
                                                total_pkt_len / 2, base, total_pkt_len & 1);

        sendipPkt(src_ipaddr, tcpType, (uint8_t *)&resent_pkt->eth_hdr, total_pkt_len, dst_ipaddr);
    }
}

// need to have shared rw_mtx
void tcp_socket::get_sdbuf_data(void *dst, uint start, uint leng)
{
    assert(sd_data_end - unack_seq >= leng && leng <= tcp_buffer_len - 1);
    assert(send_buf || leng == 0);

    start &= tcp_buffer_len - 1;
    char *ddst = (char *)dst;

    while (leng)
    {
        memmove(ddst, send_buf + start, std::min(tcp_buffer_len - start, leng));
        ddst += std::min(tcp_buffer_len - start, leng);
        leng -= std::min(tcp_buffer_len - start, leng);
        start = 0;
    }
}

// need to have shared rw_mtx
void tcp_socket::get_rcvbuf_data(void *dst, uint start, uint leng)
{
    assert(next_rev - rev_data_start >= leng && leng <= tcp_buffer_len - 1);
    assert(rev_buf || leng == 0);
    char *ddst = (char *)dst;

    start &= tcp_buffer_len - 1;
    while (leng)
    {
        memmove(ddst, rev_buf + start, std::min(tcp_buffer_len - start, leng));
        ddst += std::min(tcp_buffer_len - start, leng);
        leng -= std::min(tcp_buffer_len - start, leng);
        start = 0;
    }
}

void tcp_socket::write_rcvbuf_data(const void *dst, uint start, uint leng)
{
    assert(start + leng - rev_data_start < tcp_buffer_len && leng < tcp_buffer_len);
    if (!rev_buf)
        rev_buf = (char *)malloc(tcp_buffer_len);

    start &= tcp_buffer_len - 1;
    char *ddst = (char *)dst;

#ifdef debug
    printf("write_start : %u, leng : %u\n", start, leng);
#endif
    while (leng)
    {
        memmove(rev_buf + start, ddst, std::min(leng, tcp_buffer_len - start));
        ddst += std::min(tcp_buffer_len - start, leng);
        leng -= std::min(tcp_buffer_len - start, leng);
        start = 0;
    }
}

void tcp_socket::write_sd_buf_data(const void *dst, uint start, uint leng)
{
    assert(start + leng - unack_seq < tcp_buffer_len && leng < tcp_buffer_len);
    if (!send_buf)
        send_buf = (char *)malloc(tcp_buffer_len);

    start &= tcp_buffer_len - 1;
    char *ddst = (char *)dst;

    while (leng)
    {
        memmove(send_buf + start, ddst, std::min(leng, tcp_buffer_len - start));
        ddst += std::min(tcp_buffer_len - start, leng);
        leng -= std::min(tcp_buffer_len - start, leng);
        start = 0;
    }
}

// unique ptr->rw_mtx, caller set ptr->send_closed 1
int tcp_socket::send_tcp_fin_pkt(tcp_socket_ptr &myself)
{
    while (send_tcp_ack_pkt(send_type::general, myself))
        ;
    return 0;
}

// unique ptr->rw_mtx, only called because of unknown syn packet or ack closed listen socket
// hdr, payload_len is received header, payload_len of other side
int send_tcp_rst_pkt(uint src_ipaddr, uint dst_ipaddr, const tcphdr *hdr, uint payload_len)
{
    tcp_packet_ptr pkt_ptr{(tcp_packet *)calloc(1, sizeof(tcp_packet)), &free};
    pkt_ptr->tcp_hdr.source = hdr->dest;
    pkt_ptr->tcp_hdr.dest = hdr->source;
    pkt_ptr->tcp_hdr.seq = hdr->ack_seq;
    pkt_ptr->tcp_hdr.ack_seq = little2big(little2big<uint>(hdr->seq) + payload_len + hdr->syn + hdr->fin);
    pkt_ptr->tcp_hdr.doff = 5;
    pkt_ptr->tcp_hdr.ack = 1;
    pkt_ptr->tcp_hdr.rst = 1;
    pkt_ptr->tcp_hdr.window = 0;

    uint base = little2big<uint16_t>(src_ipaddr & 0xffff) + little2big<uint16_t>(src_ipaddr >> 16) +
                little2big<uint16_t>(dst_ipaddr & 0xffff) + little2big<uint16_t>(dst_ipaddr >> 16) +
                (tcpType << 8) + little2big<uint16_t>(pkt_ptr->tcp_hdr.doff * 4); // tcp length = 0
    pkt_ptr->tcp_hdr.check = getChecksum((uint16_t *)&pkt_ptr->tcp_hdr, pkt_ptr->tcp_hdr.doff * 4 / sizeof(uint16_t), base);
    sendipPkt(src_ipaddr, tcpType, (uint8_t *)&pkt_ptr->eth_hdr, pkt_ptr->tcp_hdr.doff * 4, dst_ipaddr);
    return 0;
}

// return number of cancelled packet for checking
int tcp_socket::update_unack_seq(uint ack_number, tcp_socket_ptr &myself)
{
    assert(ack_number - unack_seq <= next_send_seq - unack_seq);
    int num = 0;
    unack_seq = ack_number;

    while (!resent_queue.empty())
    {
        uint payload_len = resent_queue[0]->data_len - (resent_queue[0]->tcp_hdr.doff - 5) * 4;

        if (resent_queue[0]->tcp_hdr.fin || resent_queue[0]->tcp_hdr.syn)
            ++payload_len;
        uint pkt_seq = little2big<uint>(resent_queue[0]->tcp_hdr.seq);
        if (unack_seq - pkt_seq >= payload_len)
        {
            resent_queue.pop_front();
            ++num;
        }
        else
            break;
    }
#ifdef debug2
    printf("other_ack : %u, resent_queue_len : %u\n", ack_number, (uint)resent_queue.size());
#endif
    if (num)
    {
        assert(clock);
        //rto = 1;
        if (!resent_queue.empty()) // add a new clock if resent_queue is not empty
        {
            tcp_timer_tree_mtx.lock();
            erase_clock(this);
            clock = new tcp_timer{ticks, default_rto, myself};
            timer_tree.insert(tcp_timer_ptr{clock});
            tcp_timer_tree_mtx.unlock();
        }
        else
        {
            tcp_timer_tree_mtx.lock();
            erase_clock(this);
            tcp_timer_tree_mtx.unlock();
            clock = NULL;
        }
    }
    return num;
}

// here length of fin included in payload_len
int tcp_socket::rcv_data(uint seq_number, uint payload_len, const uint8_t *pure_data, uint has_fin /*=0*/)
{
    if (payload_len == 0)
        return 0;
    uint rcv_start, tmp_len = payload_len;
#ifdef debug3
    printf("orignal rcv_data_start : %u, next_rcv : %u, rcv_data_end : %u, has_fin : %u\n",
           rev_data_end, next_rev, rev_data_end, has_fin);
#endif
    std::tie(rcv_start, payload_len) = judge(rev_data_start,
                                             rev_data_start + tcp_buffer_len - 1, seq_number, seq_number + payload_len);
    if (payload_len == 0 || (rcv_start == seq_number && payload_len < tmp_len))
        return out_of_window_data;
    if (has_fin)
        rcv_closed = 1;
    write_rcvbuf_data(pure_data + rcv_start - seq_number, rcv_start, payload_len - has_fin);

    if (rev_data_end - rcv_start < payload_len)
        rev_data_end = rcv_start + payload_len;
    if (next_rev - rcv_start < payload_len)
    {
        next_rev = rcv_start + payload_len;
        for (auto iterator = ooo_data.begin(); iterator != ooo_data.end();) // merge ooo_data
        {
            if (next_rev - iterator->first < iterator->second)
            {
                next_rev = iterator->first + iterator->second;
                iterator = ooo_data.erase(iterator);
            }
            else if (next_rev - iterator->first < tcp_buffer_len)
            {
                iterator = ooo_data.erase(iterator);
            }
            else
                break;
        }
#ifdef debug3
        printf("orignal rcv_data_start : %u, next_rcv : %u, rcv_data_end : %u, has_fin : %u\n",
               rev_data_end, next_rev, rev_data_end, has_fin);
#endif
        return 0;
    }
    else if (next_rev - rcv_start > tcp_buffer_len)
    { // receive ooo_data
        ooo_data[rcv_start] = std::max(ooo_data[rcv_start], payload_len);
#ifdef debug3
        printf("orignal rcv_data_start : %u, next_rcv : %u, rcv_data_end : %u, has_fin : %u\n",
               rev_data_end, next_rev, rev_data_end, has_fin);
#endif
        return out_of_order_data;
    }
    return stale_data;
}

// have acquired unique ptr->rw_mtx
// called by receiving ack pkt or fin + ack pkt
int tcp_socket::rcv_ack_pkt_established(const uint8_t *data, uint pkt_len, tcp_socket_ptr &myself)
{
    assert(status == tcp_status::ESTABLISHED);

    const tcphdr *hdr = (const tcphdr *)data;
    uint ack_number = little2big<uint>(hdr->ack_seq);
    if (ack_number - unack_seq > next_send_seq - unack_seq)
    {
#ifdef debug3
        assert(false);
#endif
        return corrupted_pkt;
    }
    if (rcv_data(little2big<uint>(hdr->seq), pkt_len - hdr->doff * 4 + hdr->fin, data + hdr->doff * 4, hdr->fin) == out_of_window_data)
    {
#ifdef debug3             // get a packet + ack lost + upper app get payload immediately
        assert(false);    
#endif                    // subsequent retransmission will be considered as out_of_window data, but not a corrupted pkt
        if (pkt_len - hdr->doff * 4 != 0 || hdr->fin) // if payload != 0, need to send ack
            send_tcp_ack_pkt(send_type::necessary, myself);
        return 0;          
        //return corrupted_pkt;
    }
    update_unack_seq(ack_number, myself);
    window_size = little2big<uint16_t>(hdr->window);
    if (next_rev == rev_data_end && rcv_closed)
    { // all data has been received
        status = tcp_status::CLOSE_WAIT;
        assert(ooo_data.empty());
        //rcv_closed = 1;
    }

    if (pkt_len - hdr->doff * 4 != 0 || hdr->fin) // if payload != 0, need to send ack
        send_tcp_ack_pkt(send_type::necessary, myself);
    while (send_tcp_ack_pkt(send_type::general, myself))
        ;

    return 0;
}

int tcp_socket::rcv_ack_pkt_close_wait(const tcphdr *hdr, tcp_socket_ptr &myself)
{
    assert(rev_data_end == next_rev);
    uint ack_number = little2big<uint>(hdr->ack_seq);
    if (ack_number - unack_seq > next_send_seq - unack_seq)
        return corrupted_pkt;
    update_unack_seq(ack_number, myself);
    window_size = little2big<uint16_t>(hdr->window);
    if (hdr->fin)
        send_tcp_ack_pkt(send_type::necessary, myself);
    while (send_tcp_ack_pkt(send_type::general, myself))
        ;
    return 0;
}

// have acquired unique ptr->rw_mtx
// called by receiving ack pkt or fin + ack pkt
int tcp_socket::rcv_ack_pkt_fin_wait(const uint8_t *data, uint pkt_len, tcp_socket_ptr &myself)
{
    assert(status == tcp_status::FIN_WAIT_1 || status == tcp_status::FIN_WAIT_2);
    assert(status == tcp_status::FIN_WAIT_1 || unack_seq == sd_data_end);
    assert(next_send_seq == sd_data_end);

    const tcphdr *hdr = (const tcphdr *)data;
    uint ack_number = little2big<uint>(hdr->ack_seq);
    if (ack_number - unack_seq > next_send_seq - unack_seq)
        return corrupted_pkt;
    if (rcv_data(little2big<uint>(hdr->seq), pkt_len - hdr->doff * 4 + hdr->fin, data + hdr->doff * 4, hdr->fin) == out_of_window_data)
        return corrupted_pkt;
    update_unack_seq(ack_number, myself);
    window_size = little2big<uint16_t>(hdr->window);

    if (unack_seq == sd_data_end)
    { // all sent data has been received by other side
        status = tcp_status::FIN_WAIT_2;
        if (next_rev == rev_data_end && rcv_closed)
        { // all data has been received
            status = tcp_status::TIME_WAIT;
            assert(ooo_data.empty() && !clock && resent_queue.empty());

            tcp_timer_tree_mtx.lock(); // empty clock for time_wait
            timer_tree.insert(tcp_timer_ptr{new tcp_timer{ticks, default_rto, myself}});
            tcp_timer_tree_mtx.unlock();
        }
    }
    if (pkt_len + hdr->fin - hdr->doff * 4 != 0)
        send_tcp_ack_pkt(send_type::necessary, myself);

    /*while (send_tcp_ack_pkt(send_type::general))
        ;*/
    return 0;
}

// have acquired unique ptr->rw_mtx
int tcp_socket::rcv_ack_pkt_last_ack(const tcphdr *hdr, tcp_socket_ptr &myself)
{
    assert(status == tcp_status::LAST_ACK);
    assert(send_closed && rcv_closed);
    assert(next_rev == rev_data_end);

    uint ack_number = little2big<uint>(hdr->ack_seq);
    if (ack_number - unack_seq > next_send_seq - unack_seq)
        return corrupted_pkt;
    if (little2big<uint>(hdr->seq) != next_rev)
        return corrupted_pkt;
    update_unack_seq(ack_number, myself);
    window_size = little2big<uint16_t>(hdr->window);
    if (ack_number == sd_data_end)
        status = closed ? tcp_status::ORPHAN : tcp_status::NO_USE;
    return 0;
}

// need unique sock->rw_mtx, no need for sockmap_mtx,
// sock->src_ipaddr is constant here (possible status: established)
// caller has updated ack number, only send new packet intead of retransmission
int tcp_socket::send_tcp_ack_pkt(send_type type, tcp_socket_ptr &myself) // return payload_len
{
    uint data_len = std::min(sd_data_end - next_send_seq,
                             window_size < next_send_seq - unack_seq ? 0 : window_size - (next_send_seq - unack_seq));
    uint need_fin = 0;
    data_len = std::min(data_len, (uint)other_mss); // min(available data, window limit, mss limit)
    if (send_closed && (status == tcp_status::CLOSE_WAIT || status == tcp_status::ESTABLISHED) &&
        data_len + next_send_seq == sd_data_end)
    {
        need_fin = 1;
        status = status == tcp_status::CLOSE_WAIT ? tcp_status::LAST_ACK : tcp_status::FIN_WAIT_1;
    }
    else if (window_size == 0 && sd_data_end > next_send_seq && resent_queue.empty()) // window probing
    {
        assert(need_fin == 0 && data_len == 0);
        assert(!clock);
        data_len = 1;
    }
    else if (data_len == 0 && type == send_type::general)
        return 0;

    tcp_packet_ptr pkt_ptr((tcp_packet *)calloc(1, sizeof(tcp_packet) + data_len), &free);
    tcp_packet *tcp_pkt_buffer = pkt_ptr.get();
    get_sdbuf_data(tcp_pkt_buffer + 1, next_send_seq, data_len);
    get_tcp_ack_hdr(this, &tcp_pkt_buffer->tcp_hdr, data_len, next_send_seq + data_len == sd_data_end && data_len, need_fin);
    sendipPkt(src_ipaddr, tcpType, (uint8_t *)&tcp_pkt_buffer->eth_hdr, sizeof(tcphdr) + data_len,
              dst_ipaddr);
    next_send_seq += data_len + need_fin; // length of fin is 1, buf not included in buffer
    sd_data_end += need_fin;

    if (data_len == 0 && need_fin == 0)
    {
        return 0;
    }
    else
    {
        tcp_pkt_buffer->data_len = data_len;
        resent_queue.push_back(std::move(pkt_ptr));
        if (!clock)
        {
            tcp_timer_tree_mtx.lock();
            clock = new tcp_timer{ticks, default_rto, myself};
            timer_tree.insert(tcp_timer_ptr{clock});
            tcp_timer_tree_mtx.unlock();
        }
        return data_len;
    }
}

uint16_t get_mss(const tcphdr *hdr)
{
    uint16_t ret = 0, option_len = (hdr->doff - 5) * 4;
    uint16_t *mss_ptr;
    uint8_t *option = (uint8_t *)(hdr + 1);
    while (*option && !ret && option_len)
    {
        switch (*option)
        {
        case TCP_MAXSEG:
            mss_ptr = (uint16_t *)option + 1;
            ret = little2big<uint16_t>(*mss_ptr);
            option_len -= 4;
            option += 4;
            break;

        case 0x1:
            option += 1;
            option_len--;
            break;

        default:
            uint8_t leng = *(option + 1);
            option_len -= leng;
            option += leng;
            break;
        }
    }
    return ret;
}

// need sock->rw_mtx, no need for sockmap_mtx,
// sock->src_ipaddr is constant here (possible status: connection, syn_rcvd)
void get_tcp_syn_hdr(tcp_socket *sock, tcphdr *hdr, int need_ack /*=0*/)
{ // memset(hdr, 0, sizeof(tcphdr)) provided by caller
    mss_option *mss_opt = (mss_option *)(hdr + 1);
    mss_opt->kind = TCP_MAXSEG;
    mss_opt->length = 4;
    mss_opt->mss = little2big<uint16_t>(sock->my_mss);

    hdr->source = little2big<uint16_t>(sock->src_port);
    hdr->dest = little2big<uint16_t>(sock->dst_port);
    hdr->seq = little2big<uint>(sock->init_seq);
    hdr->ack_seq = need_ack ? little2big(sock->other_init_seq + 1) : 0;
    hdr->doff = 6; // 20(base_header) + 4(mss)  / 4
    hdr->syn = 1;
    hdr->ack = need_ack;
    hdr->window = little2big<uint16_t>(tcp_buffer_len - 1);

    uint base = little2big<uint16_t>(sock->src_ipaddr & 0xffff) + little2big<uint16_t>(sock->src_ipaddr >> 16) +
                little2big<uint16_t>(sock->dst_ipaddr & 0xffff) + little2big<uint16_t>(sock->dst_ipaddr >> 16) +
                (tcpType << 8) + little2big<uint16_t>(hdr->doff * 4); // tcp length = 0
    hdr->check = getChecksum((uint16_t *)hdr, hdr->doff * 4 / sizeof(uint16_t), base);

    return;
}

// need sock->rw_mtx, no need for sockmap_mtx,
// sock->src_ipaddr is constant here (possible status: established)
// now only called by send_tcp_ack_pkt (send new packet), data need to be stored after hdr in advance
void get_tcp_ack_hdr(tcp_socket *sock, tcphdr *hdr, uint payload_len, uint need_push /*=0*/, uint need_fin /*=0*/)
{
    hdr->source = little2big<uint16_t>(sock->src_port);
    hdr->dest = little2big<uint16_t>(sock->dst_port);
    hdr->seq = little2big<uint>(sock->next_send_seq); // send new packet
    hdr->ack_seq = little2big<uint>(sock->next_rev);
    hdr->doff = 5;
    hdr->ack = 1;
    hdr->fin = need_fin;
    hdr->psh = need_push;
    hdr->window = little2big<uint16_t>(tcp_buffer_len - 1 - (sock->next_rev - sock->rev_data_start));

    uint base = little2big<uint16_t>(sock->src_ipaddr & 0xffff) + little2big<uint16_t>(sock->src_ipaddr >> 16) +
                little2big<uint16_t>(sock->dst_ipaddr & 0xffff) + little2big<uint16_t>(sock->dst_ipaddr >> 16) +
                (tcpType << 8) + little2big<uint16_t>(hdr->doff * 4 + payload_len);
    hdr->check = getChecksum((uint16_t *)hdr, (hdr->doff * 4 + payload_len) / 2, base, payload_len & 1);

    return;
}

// need sock->rw_mtx, no need for sockmap_mtx,
// sock->src_ipaddr is constant here (possible status: syn_rcvd)
// caller is rcv_tcp_syn_pkt
int send_tcp_syn_ack_pkt(tcp_socket_ptr &ptr)
{
    tcp_packet_ptr pkt_ptr((tcp_packet *)calloc(1, sizeof(tcp_packet) + 4), &free);
    tcp_packet *tcp_syn_ack_pkt = pkt_ptr.get();
    get_tcp_syn_hdr(ptr.get(), &tcp_syn_ack_pkt->tcp_hdr, 1);
    sendipPkt(ptr->src_ipaddr, tcpType, (uint8_t *)&tcp_syn_ack_pkt->eth_hdr, sizeof(tcphdr) + 4, ptr->dst_ipaddr);

    tcp_syn_ack_pkt->data_len = 4;
    ptr->resent_queue.push_back(std::move(pkt_ptr)); // add syn_ack packet into retransmission queue

    assert(!ptr->clock);
    tcp_timer_tree_mtx.lock();
    ptr->clock = new tcp_timer{ticks, default_rto, ptr};
    timer_tree.insert(tcp_timer_ptr{ptr->clock}); // set a clock for resent packet
    tcp_timer_tree_mtx.unlock();

    return 0;
}

// src_ipaddr -> local host, dst_ipaddr -> remote host
// packet_len is total length including tcp header
int rcv_tcp_packet(uint src_ipaddr, uint dst_ipaddr, const uint8_t *data, uint16_t packet_len)
{
    const tcphdr *hdr = (const tcphdr *)data;
    if (packet_len < hdr->doff * 4)
    {
        return corrupted_pkt;
    }
    uint base = little2big<uint16_t>(src_ipaddr & 0xffff) + little2big<uint16_t>(src_ipaddr >> 16) +
                little2big<uint16_t>(dst_ipaddr & 0xffff) + little2big<uint16_t>(dst_ipaddr >> 16) +
                (tcpType << 8) + little2big<uint16_t>(packet_len);
    /*
    if (check((const uint16_t *)data, packet_len / 2, base, packet_len & 1) == 0)
    {
        return corrupted_pkt;             // tcp checksum offload ?
    }*/

    uint16_t my_port = little2big<uint16_t>(hdr->dest);
    uint16_t other_port = little2big<uint16_t>(hdr->source);
    //tcp_socket_ptr ptr;
    if (hdr->rst == 1)
        rcv_tcp_rst_packet(src_ipaddr, dst_ipaddr, my_port, other_port, hdr);
    else if (hdr->syn == 1 && hdr->ack == 1)
        rcv_tcp_syn_ack_packet(src_ipaddr, dst_ipaddr, my_port, other_port, hdr);
    else if (hdr->syn == 1)
        rcv_tcp_syn_packet(src_ipaddr, dst_ipaddr, my_port, other_port, hdr);
    else
        rcv_tcp_ack_packet(src_ipaddr, dst_ipaddr, my_port, other_port, data, packet_len);
    return 0;
}

int rcv_tcp_rst_packet(uint my_ipaddr, uint dst_ipddr, uint16_t my_port, uint16_t dst_port, const tcphdr *hdr)
{
    tcp_socket_ptr ptr;
    shared_lock lock(sockmap_mtx);
    for (auto &p : fd_to_sock)
    {
        p.second->rw_mtx.lock();
        if (p.second->src_port == my_port && p.second->src_ipaddr == my_ipaddr &&
            p.second->dst_port == dst_port && p.second->dst_ipaddr == dst_ipddr)
        {
            ptr = p.second;
            goto found;
        }
        p.second->rw_mtx.unlock();
    }
    return unknown_connect_request;

found: // now have unique ptr->rw_mtx
    switch (ptr->status)
    {
    case tcp_status::CLOSED:
    case tcp_status::LISTEN:
    case tcp_status::TIME_WAIT:
    case tcp_status::NO_USE:
    case tcp_status::OTHER_ABORT:
    case tcp_status::ORPHAN:
        break;
    case tcp_status::SYN_SENT:
        ptr->cond_connect.notify_one(); // notify connecting thread
        break;
    default:
        if (ptr->clock)
        {
            tcp_timer_tree_mtx.lock();
            erase_clock(ptr.get());
            tcp_timer_tree_mtx.unlock();
            ptr->clock = NULL;
        }
        ptr->status = ptr->closed ? tcp_status::ORPHAN : tcp_status::NO_USE;
    }
    ptr->cond_send.notify_all();
    ptr->cond_recv.notify_all();
#ifdef block_close
    ptr->cond_close.notify_all();
#endif
    ptr->rw_mtx.unlock();
    return 0;
}

int rcv_tcp_ack_packet(uint my_ipaddr, uint dst_ipddr, uint16_t my_port, uint16_t dst_port, const uint8_t *data, uint pkt_len)
{
#ifdef debug3
    static int i;
    //if((++i % 100) == 0){
    const tcphdr *tcp_hdr = (const tcphdr *)data;
    std::cout << "pkt " << ++i << " :" << std::endl;
    printf("seq number: %u , payload_len : %u\n", little2big(tcp_hdr->seq), pkt_len - tcp_hdr->doff * 4);
#endif
    //}
    // TODO

    tcp_socket_ptr ptr;
    uint sockfd;
    shared_lock lock(sockmap_mtx);
    for (auto &p : fd_to_sock)
    {
        p.second->rw_mtx.lock();
        if (p.second->src_port == my_port && p.second->src_ipaddr == my_ipaddr &&
            p.second->dst_port == dst_port && p.second->dst_ipaddr == dst_ipddr)
        {
            ptr = p.second;
            sockfd = p.first;
            goto found;
        }
        p.second->rw_mtx.unlock();
    }
    send_tcp_rst_pkt(my_ipaddr, dst_ipddr, (const tcphdr *)data, pkt_len - ((const tcphdr *)data)->doff * 4);
    return unknown_connect_request;

found:                                       // have unique ptr->rw_mtx and shared sockmap_mtx
    if (ptr->status == tcp_status::SYN_RCVD) // special case
    {
        const tcphdr *hdr = (const tcphdr *)data;
        uint ack_number = little2big<uint>(hdr->ack_seq);
        if (ack_number - ptr->unack_seq > ptr->next_send_seq - ptr->unack_seq)
        {
            ptr->rw_mtx.unlock();
            return corrupted_pkt;
        }
        if (ptr->rcv_data(little2big<uint>(hdr->seq),
                          pkt_len - hdr->doff * 4 + hdr->fin, data + hdr->doff * 4, hdr->fin) == out_of_window_data)
        {
            ptr->rw_mtx.unlock();
            return corrupted_pkt;
        }
        assert(ptr->update_unack_seq(ack_number, ptr) == 1);
        if (fd_to_sock.count(ptr->mother_fd) == 0)
        {
            send_tcp_rst_pkt(my_ipaddr, dst_ipddr, hdr, pkt_len - hdr->doff * 4);
            tcp_timer_tree_mtx.lock();
            erase_clock(ptr.get());
            tcp_timer_tree_mtx.unlock();
            ptr->clock = NULL;
            ptr->closed = 1;
            ptr->status = tcp_status::ORPHAN;
            ptr->rw_mtx.unlock();
            return 0;
        }
        tcp_socket_ptr mother = fd_to_sock[ptr->mother_fd];
        mother->rw_mtx.lock();
        lock.unlock();
        if (mother->status != tcp_status::LISTEN)
        {
            assert(mother->status == tcp_status::ORPHAN);
            send_tcp_rst_pkt(my_ipaddr, dst_ipddr, hdr, pkt_len - hdr->doff * 4);
            tcp_timer_tree_mtx.lock();
            erase_clock(ptr.get());
            tcp_timer_tree_mtx.unlock();
            ptr->clock = NULL;
            ptr->closed = 1;
            ptr->status = tcp_status::ORPHAN;
            mother->rw_mtx.unlock();
            ptr->rw_mtx.unlock();
            return 0;
        }
        mother->accept_queue.push(sockfd);
        mother->cond_accept.notify_one(); // signal some thread blocked because of empty accept_queue
        mother->rw_mtx.unlock();

        if (pkt_len - hdr->doff * 4 != 0)
            ptr->send_tcp_ack_pkt(tcp_socket::send_type::necessary, ptr);
        ptr->status = tcp_status::ESTABLISHED;
        ptr->window_size = little2big<uint16_t>(hdr->window);
        ptr->rcv_closed = hdr->fin;
        if (hdr->fin && ptr->next_rev == ptr->rev_data_end)
            ptr->status = tcp_status::CLOSE_WAIT;
        ptr->rw_mtx.unlock();
        return 0;
    }

    lock.unlock();
    switch (ptr->status)
    {
    case tcp_status::ESTABLISHED:
        ptr->rcv_ack_pkt_established(data, pkt_len, ptr);
        break;
    case tcp_status::CLOSE_WAIT:
        ptr->rcv_ack_pkt_close_wait((const tcphdr *)data, ptr);
        break;
    case tcp_status::FIN_WAIT_1:
    case tcp_status::FIN_WAIT_2:
        ptr->rcv_ack_pkt_fin_wait(data, pkt_len, ptr);
        break;
    case tcp_status::LAST_ACK:
        ptr->rcv_ack_pkt_last_ack((const tcphdr *)data, ptr);
        break;
    case tcp_status::TIME_WAIT:
        assert(ptr->send_tcp_ack_pkt(tcp_socket::send_type::necessary, ptr) == 0);
        break;
    default:
        //std::cout << "status : " << (uint)ptr->status << std::endl;
        send_tcp_rst_pkt(my_ipaddr, dst_ipddr, (const tcphdr *)data, pkt_len - ((const tcphdr *)data)->doff * 4);
    }
    ptr->cond_recv.notify_all();
    ptr->cond_send.notify_all();
#ifdef block_close
    ptr->cond_close.notify_all();
#endif
    ptr->rw_mtx.unlock();
    return 0;
}

int rcv_tcp_syn_packet(uint my_ipaddr, uint dst_ipddr, uint16_t my_port, uint16_t dst_port, const tcphdr *hdr)
{
    uint16_t other_mss;
    if (hdr->doff <= 5 || (other_mss = get_mss(hdr)) == 0)
    {
        return corrupted_pkt;
    }

    tcp_socket_ptr ptr;
    uint mother_fd;
    unique_lock lock(sockmap_mtx);
    for (auto &p : fd_to_sock)
    {
        p.second->rw_mtx.lock_shared();
        if (p.second->status == tcp_status::LISTEN && p.second->src_port == my_port &&
            (p.second->src_ipaddr == 0 || p.second->src_ipaddr == my_ipaddr))
        {
            assert(!ptr);
            ptr = p.second;
            mother_fd = p.first;
            p.second->rw_mtx.unlock_shared();
        }
        else if (p.second->src_port == my_port && p.second->src_ipaddr == my_ipaddr &&
                 p.second->dst_port == dst_port && p.second->dst_ipaddr == dst_ipddr)
        {
            p.second->rw_mtx.unlock_shared();
            return unknown_connect_request;
        }
        else
        {
            p.second->rw_mtx.unlock_shared();
        }
    }
    if (ptr)
    {
        goto found;
    }
    return unknown_connect_request;

found: // unique sockmap_mtx, shared ptr->rw_mtx has acquired
    ptr->rw_mtx.lock_shared();
    if (ptr->status != tcp_status::LISTEN)
    {
        ptr->rw_mtx.unlock_shared();
        return unknown_connect_request;
    }
    if (ptr->backlog <= ptr->accept_queue.size())
    {
        ptr->rw_mtx.unlock_shared();
        return busy_connect_request;
    }

    uint new_sockfd;
    tcp_socket_ptr new_sock(new tcp_socket{});
    new_sock->src_ipaddr = my_ipaddr;
    new_sock->src_port = my_port;
    if ((new_sockfd = add_socket(new_sock)) == -1)
    {
        ptr->rw_mtx.unlock_shared();
        return busy_sockfd;
    }
    lock.unlock();
    //ptr->accept_queue.push(new_sockfd);
    new_sock->rw_mtx.lock();
    ptr->rw_mtx.unlock_shared(); // now only have unique new_sock->rw_mtx

    new_sock->dst_ipaddr = dst_ipddr;
    new_sock->dst_port = dst_port;
    new_sock->status = tcp_status::SYN_RCVD;
    new_sock->mother_fd = mother_fd;

    new_sock->other_init_seq = little2big<uint>(hdr->seq);
    new_sock->rev_data_start = new_sock->other_init_seq + 1;
    new_sock->rev_data_end = new_sock->other_init_seq + 1;
    new_sock->next_rev = new_sock->other_init_seq + 1;

    engine_mtx.lock();
    new_sock->init_seq = init_seq_engine();
    engine_mtx.unlock();
    new_sock->unack_seq = new_sock->init_seq;
    new_sock->next_send_seq = new_sock->init_seq + 1;
    new_sock->sd_data_end = new_sock->init_seq + 1;

    new_sock->window_size = little2big<uint16_t>(hdr->window);
    new_sock->other_mss = other_mss;

    send_tcp_syn_ack_pkt(new_sock);
    new_sock->rw_mtx.unlock();
    return 0;
}

int rcv_tcp_syn_ack_packet(uint my_ipaddr, uint dst_ipddr, uint16_t my_port, uint16_t dst_port, const tcphdr *hdr)
{
    uint16_t other_mss;
    if (hdr->doff <= 5 || (other_mss = get_mss(hdr)) == 0)
    {
        return corrupted_pkt;
    }

    tcp_socket_ptr ptr;
    shared_lock lock(sockmap_mtx);
    for (auto &p : fd_to_sock)
    {
        p.second->rw_mtx.lock();
        if (p.second->status != tcp_status::SYN_SENT || p.second->src_ipaddr != my_ipaddr || p.second->src_port != my_port ||
            p.second->dst_ipaddr != dst_ipddr || p.second->dst_port != dst_port)
        {
            p.second->rw_mtx.unlock();
            continue;
        }
        if (little2big<uint>(hdr->ack_seq) != p.second->init_seq + 1)
        { // check if ack_seq is right
            p.second->rw_mtx.unlock();
            continue;
        }
        ptr = p.second;
        goto found;
    }
    return unknown_connect_request;

found:
    lock.unlock(); // now only have unique ptr->rw_mtx
    ptr->status = tcp_status::ESTABLISHED;

    ptr->other_init_seq = little2big<uint>(hdr->seq);
    ptr->next_rev = ptr->other_init_seq + 1;
    ptr->rev_data_start = ptr->other_init_seq + 1;
    ptr->rev_data_end = ptr->other_init_seq + 1;

    ptr->unack_seq += 1; // length of syn pkt = 1

    ptr->window_size = little2big<uint16_t>(hdr->window);
    ptr->other_mss = other_mss;

    ptr->send_tcp_ack_pkt(tcp_socket::send_type::necessary, ptr);
    ptr->cond_connect.notify_one();
    ptr->rw_mtx.unlock();
    return 0;
}

#ifdef MEMORY
void print_resource()
{
    cout << "tcp_socket_create: " << tcp_socket_create << endl;
    cout << "tcp_socket_delete: " << tcp_socket_delete << endl;
    cout << "tcp_timer_create: " << tcp_timer_create << endl;
    cout << "tcp_timer_delete: " << tcp_timer_delete << endl;
}
#endif

/*void coredump_buf(uint sockfd, uint fd, uint leng)
{
    tcp_socket_ptr ptr = fd_to_sock.at(sockfd);
    uint start = ptr->rev_data_start & (tcp_buffer_len - 1);
    //write(fd, fd_to_sock.at(sockfd)->rev_buf + ,     
}*/