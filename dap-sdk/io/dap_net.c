#ifndef _WIN32
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
//#include <unistd.h> // for close
#include <fcntl.h>
//#include <sys/poll.h>
//#include <sys/select.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/stat.h>
//#define closesocket close
//typedef int SOCKET;
//#define SOCKET_ERROR    -1  // for win32 =  (-1)
//#define INVALID_SOCKET  -1  // for win32 =  (SOCKET)(~0)
// for Windows
#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <errno.h>
#include <string.h>
#include "dap_net.h"

#define LOG_TAG "dap_net"

#ifdef _WIN32
  #define poll WSAPoll
#endif

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

/**
 * @brief s_recv
 * timeout in milliseconds
 * return the number of read bytes (-1 err or -2 timeout)
 * @param sock
 * @param buf
 * @param bufsize
 * @param timeout
 * @return long
 */
long dap_net_recv(SOCKET sd, unsigned char *buf, size_t bufsize, int timeout)
{
struct pollfd fds = {.fd = sd, .events = POLLIN};
int res;

    if ( !(res = poll(&fds, 1, timeout)) )
        return -2;

    if ( (res == 1) && !(fds.revents & POLLIN))
        return -1;

    if(res < 1)
        return -1;

    if ( 0 >= (res = recv(sd, (char *)buf, bufsize, 0)) )
        printf("[s_recv] recv()->%d, errno: %d\n", res, errno);

    return res;
}
