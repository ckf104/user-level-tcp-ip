#include "tcp_timer.hpp"
#include "tcplayer.hpp"
#include <thread>

#ifdef MEMORY
int tcp_timer_create = 0, tcp_timer_delete = 0;
#endif

multiset<tcp_timer_ptr> timer_tree;
volatile uint ticks;
mutex tcp_timer_tree_mtx;

// caller need to have tcp_timer_tree_mtx
bool operator<(const tcp_timer_ptr &timer_1, const tcp_timer_ptr &tiemr_2)
{
    // avoid ticks wrapping
    return (timer_1->expire_time - ticks) < (tiemr_2->expire_time - ticks);
}

tcp_timer::tcp_timer(uint base, uint t, tcp_socket_ptr &timer_owner) : base_ticks(base), expire_time(t), ptr(timer_owner)
{
#ifdef MEMORY
    cout << "tcp_timer created" << endl;
    __sync_fetch_and_add(&tcp_timer_create, 1);
#endif
}

tcp_timer::~tcp_timer()
{
#ifdef MEMORY
    cout << "tcp_timer deleted" << endl;
    __sync_fetch_and_add(&tcp_timer_delete, 1);
#endif
}

void clock_manager()
{ // manage tcp retransmission
    while (1)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        tcp_timer_tree_mtx.lock();
        ticks++;
        for (auto timer_ptr = timer_tree.begin(); timer_ptr != timer_tree.end();)
        {
            // TODO acquire share lock and judge if resnding is needed
            tcp_timer *p = timer_ptr->get();
            if (ticks - p->expire_time - p->base_ticks > 65536) // magic number ?
            {
                break;
            }
            unique_lock socket_lock(p->ptr->rw_mtx, std::try_to_lock);
#ifdef debug4
            printf("tisks %u: ", ticks);
#endif
            if (!socket_lock)
            {
                ++timer_ptr;
#ifdef debug4
                printf("fail\n");
#endif
                continue;
            }
#ifdef debug4
            printf("succ\n");
#endif
            // now have unique ptr->rw_mtx

            //timer_ptr = timer_tree.erase(timer_ptr);   // TODO
            uint new_expire = p->expire_time * 2;
            if (new_expire > rto_limit)
            {
                if (p->ptr->closed)
                {
                    p->ptr->status = tcp_status::ORPHAN;
                }
                else
                {
                    switch (p->ptr->status)
                    {
                    case tcp_status::ESTABLISHED:
                    case tcp_status::CLOSE_WAIT:
                        p->ptr->status = tcp_status::OTHER_ABORT;
                        break;
                    case tcp_status::SYN_RCVD:
                        p->ptr->status = tcp_status::ORPHAN;
                        break;
                    case tcp_status::FIN_WAIT_1:
                    case tcp_status::FIN_WAIT_2:
                    case tcp_status::TIME_WAIT:
                    case tcp_status::LAST_ACK:
                        p->ptr->status = tcp_status::NO_USE;
                        break;
                    default:
                        assert(false);
                    }
                }
                p->ptr->clock = NULL;
                p->ptr->cond_recv.notify_all();
                p->ptr->cond_send.notify_all();
#ifdef block_close
                p->ptr->cond_close.notify_all();
#endif
            }
            else
            { // update expire_time and retransmission
                tcp_timer *new_timer = new tcp_timer{ticks, new_expire, p->ptr};
                p->ptr->clock = new_timer;
                timer_tree.insert(tcp_timer_ptr{new_timer});
                p->ptr->retransmission();
            }
            timer_ptr = timer_tree.erase(timer_ptr);
        }
        tcp_timer_tree_mtx.unlock();
    }
}

void erase_clock(tcp_socket *ptr)
{
    for (auto p = timer_tree.begin(); p != timer_tree.end(); ++p)
    {
        if ((*p)->ptr.get() == ptr)
        {
            timer_tree.erase(p);
            return;
        }
    }
    assert(false);
}