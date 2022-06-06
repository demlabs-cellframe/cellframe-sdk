#include <string.h>
#include "dap_net.h"

#define LOG_TAG "dap_net"

/**
 * @brief dap_net_resolve_host
 * @param a_host hostname
 * @param ai_family AF_INET  for ipv4 or AF_INET6 for ipv6
 * @param a_addr_out out addr (struct in_addr or struct in6_addr)
 * @param return 0 of OK, <0 Error
 */
int dap_net_resolve_host(const char *a_host, int ai_family, struct sockaddr *a_addr_out)
{
    struct addrinfo l_hints, *l_res;
    void *l_cur_addr = NULL;

    memset(&l_hints, 0, sizeof(l_hints));
    l_hints.ai_family = PF_UNSPEC;
    l_hints.ai_socktype = SOCK_STREAM;
    l_hints.ai_flags |= AI_CANONNAME;

    if ( getaddrinfo(a_host, NULL, &l_hints, &l_res) )
        return -2;

    while(l_res)
    {
        if(ai_family == l_res->ai_family)
            switch (l_res->ai_family)
            {
            case AF_INET:
                l_cur_addr = &((struct sockaddr_in *) l_res->ai_addr)->sin_addr;
                memcpy(a_addr_out, l_cur_addr, sizeof(struct in_addr));
                break;
            case AF_INET6:
                l_cur_addr = &((struct sockaddr_in6 *) l_res->ai_addr)->sin6_addr;
                memcpy(a_addr_out, l_cur_addr, sizeof(struct in6_addr));
                break;
            }
        if(l_cur_addr) {
            freeaddrinfo(l_res);
            return 0;
        }
        l_res = l_res->ai_next;
    }
    if (l_res)
        freeaddrinfo(l_res);
    return -1;
}
