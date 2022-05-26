#include <iostream>
#include "general.hpp"

uint16_t getChecksum(const uint16_t *p, int len, uint base /*=0*/, uint padding /*=0*/)
{ // the array length of p
    uint rel = base;
    for (int i = 0; i < len; ++i)
    {
        rel += p[i];
    }
    if (padding == 1)
    {
        rel += *(uint8_t *)(p + len);
    }
    while (rel > 0xffff)
    {
        uint tmp = *((uint16_t *)&rel + 1) + (rel & 0xffff);
        rel = tmp;
    }
    return ~rel;
}

bool check(const uint16_t *p, int len, uint base /*=0*/, uint padding /*=0*/)
{ // the array length of p
    return getChecksum(p, len, base, padding) == 0;
}

std::pair<uint, uint> judge(uint big_left, uint big_right, uint small_left, uint small_right)
{
    //assert(small_right - small_left <= default_mss);
    assert(big_right - big_left == tcp_buffer_len - 1);

    int case_1 = small_left - big_left < tcp_buffer_len - 1;  // first bit in section [big_left, big_right) ?
    int case_2 = big_right - small_right < tcp_buffer_len - 1;   // last bit in section [big_left, big_right) ?
    if(case_1 && case_2){
        return {small_left, small_right - small_left};
    }       
    else if(case_1){
        return {small_left, big_right - small_left};
    }
    else if(case_2){
        return {big_left, small_right - big_left};
    }
    return {big_left, 0};
}

int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    addrinfo *rel = (addrinfo *)calloc(1, sizeof(addrinfo));
    sockaddr_in *addr = (sockaddr_in *)calloc(1, sizeof(sockaddr_in));
    if (hints != NULL && (hints->ai_family != AF_INET || hints->ai_flags != 0 || hints->ai_socktype != IPPROTO_TCP))
    {
        goto bad;
    }

    addr->sin_family = AF_INET;
    uint tmp_port;
    if (service != NULL && sscanf(service, "%u", &tmp_port) != 1)
    {
        goto bad;
    }
    addr->sin_port = little2big<uint16_t>((uint16_t)tmp_port);
    if (node == NULL)
    {
        assert(inet_pton(AF_INET, "127.0.0.1", &addr->sin_addr) == 1);
    }
    else if (inet_pton(AF_INET, node, &addr->sin_addr) != 1)
    {
        goto bad;
    }
    rel->ai_addr = (sockaddr *)addr;
    rel->ai_addrlen = sizeof(sockaddr_in);
    rel->ai_canonname = NULL;
    rel->ai_family = AF_INET;
    rel->ai_flags = 0;
    rel->ai_next = NULL;
    rel->ai_protocol = IPPROTO_TCP;
    rel->ai_socktype = SOCK_STREAM;

    *res = rel;
    return 0;

bad:
    free(rel);
    free(addr);
    return EAI_SOCKTYPE;
}

int __wrap_freeaddrinfo(addrinfo *rel)
{
    while (rel)
    {
        addrinfo *tmp = rel;
        free(rel->ai_addr);
        rel = rel->ai_next;
        free(tmp);
    }
    return 0;
}