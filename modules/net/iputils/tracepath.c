/*
 * tracepath.c
 *
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License
 *    as published by the Free Software Foundation; either version
 *    2 of the License, or (at your option) any later version.
 *
 * Authors: Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <linux/errqueue.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
//#include <glib.h>

#include "iputils.h"

#ifdef USE_IDN
# include <locale.h>
# ifndef AI_IDN
#  define AI_IDN 0x0040
# endif
# ifndef NI_IDN
#  define NI_IDN 32
# endif
# define getnameinfo_flags  NI_IDN
#else
# define getnameinfo_flags  0
#endif

#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef IP_PMTUDISC_DO
# define IP_PMTUDISC_DO   3
#endif
#ifndef IPV6_PMTUDISC_DO
# define IPV6_PMTUDISC_DO 3
#endif

enum {
    MAX_PROBES = 10,

    MAX_HOPS_DEFAULT = 30,
    MAX_HOPS_LIMIT = 255,

    HOST_COLUMN_SIZE = 52,

    HIS_ARRAY_SIZE = 64,

    DEFAULT_OVERHEAD_IPV4 = 28,
    DEFAULT_OVERHEAD_IPV6 = 48,

    DEFAULT_MTU_IPV4 = 65535,
    DEFAULT_MTU_IPV6 = 128000,

    DEFAULT_BASEPORT = 44444,

    ANCILLARY_DATA_LEN = 512,
};

struct hhistory {
    int hops;
    struct timeval sendtime;
    struct timeval deltatime;
    int hop;
    char *host_namea;
    char *host_nameb;
};

struct probehdr {
    uint32_t ttl;
    struct timeval tv;
};

struct run_state {
    struct hhistory his[HIS_ARRAY_SIZE];
    int hisptr;
    struct sockaddr_storage target;
    struct addrinfo *ai;
    int socket_fd;
    socklen_t targetlen;
    uint16_t base_port;
    uint8_t ttl;
    int max_hops;
    int overhead;
    int mtu;
    void *pktbuf;
    int hops_to;
    int hops_from;
    unsigned int
    no_resolve :1,
            show_both :1,
            mapped :1;
};

/*
 * All includes, definitions, struct declarations, and global variables are
 * above.  After this comment all you can find is functions.
 */

static void data_wait(struct run_state const * const ctl)
{
    fd_set fds;
    struct timeval tv = {
        .tv_sec = 1,
        .tv_usec = 0
    };

    FD_ZERO(&fds);
    FD_SET(ctl->socket_fd, &fds);
    select(ctl->socket_fd + 1, &fds, NULL, NULL, &tv);
}

static void print_host(struct run_state const * const ctl, char const * const a,
        char const * const b)
{
    int plen;

    plen = log_printf("%s", a);
    if(ctl->show_both)
        plen += log_printf(" (%s)", b);
    if(plen >= HOST_COLUMN_SIZE)
        plen = HOST_COLUMN_SIZE - 1;
    log_printf("%*s", HOST_COLUMN_SIZE - plen, "");
}

static int recverr(struct run_state * const ctl)
{
    ssize_t recv_size;
    struct probehdr rcvbuf;
    char cbuf[ANCILLARY_DATA_LEN];
    struct cmsghdr *cmsg;
    struct sock_extended_err *e;
    struct sockaddr_storage addr;
    struct timeval tv;
    struct timeval *rettv;
    struct timeval *deltatv;
    int slot = 0;
    int rethops;
    int sndhops;
    int progress = -1;
    int broken_router;
    char hnamebuf[NI_MAXHOST] = "";
    struct iovec iov = {
        .iov_base = &rcvbuf,
        .iov_len = sizeof(rcvbuf)
    };
    struct msghdr msg;
    const struct msghdr reset = {
        .msg_name = (uint8_t *) &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cbuf,
        .msg_controllen = sizeof(cbuf),
        0
    };

    restart:
    memset(&rcvbuf, -1, sizeof(rcvbuf));
    msg = reset;

    gettimeofday(&tv, NULL);
    recv_size = recvmsg(ctl->socket_fd, &msg, MSG_ERRQUEUE);
    if(recv_size < 0) {
        if(errno == EAGAIN)
            return progress;
        goto restart;
    }

    progress = ctl->mtu;

    rethops = -1;
    sndhops = -1;
    e = NULL;
    rettv = NULL;
    deltatv = NULL;
    broken_router = 0;

    slot = -ctl->base_port;
    switch (ctl->ai->ai_family) {
    case AF_INET6:
        slot += ntohs(((struct sockaddr_in6 *) &addr)->sin6_port);
        break;
    case AF_INET:
        slot += ntohs(((struct sockaddr_in *) &addr)->sin_port);
        break;
    }

    if(slot >= 0 && slot < (HIS_ARRAY_SIZE - 1) && ctl->his[slot].hops) {
        sndhops = ctl->his[slot].hops;
        rettv = &ctl->his[slot].sendtime;
        deltatv = &ctl->his[slot].deltatime;
        ctl->his[slot].hop = sndhops;
        ctl->his[slot].hops = 0;
    }
    if(recv_size == sizeof(rcvbuf)) {
        if(rcvbuf.ttl == 0 || rcvbuf.tv.tv_sec == 0)
            broken_router = 1;
        else {
            sndhops = rcvbuf.ttl;
            rettv = &rcvbuf.tv;
        }
    }

    for(cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        switch (cmsg->cmsg_level) {
        case SOL_IPV6:
            switch (cmsg->cmsg_type) {
            case IPV6_RECVERR:
                e = (struct sock_extended_err *) CMSG_DATA(cmsg);
                break;
            case IPV6_HOPLIMIT:
                #ifdef IPV6_2292HOPLIMIT
            case IPV6_2292HOPLIMIT:
                #endif
                memcpy(&rethops, CMSG_DATA(cmsg), sizeof(rethops));
                break;
            default:
                log_printf("cmsg6:%d\n ", cmsg->cmsg_type);
            }
            break;
        case SOL_IP:
            switch (cmsg->cmsg_type) {
            case IP_RECVERR:
                e = (struct sock_extended_err *) CMSG_DATA(cmsg);
                break;
            case IP_TTL:
                rethops = *(uint8_t *) CMSG_DATA(cmsg);
                break;
            default:
                log_printf("cmsg4:%d\n ", cmsg->cmsg_type);
            }
        }
    }
    if(e == NULL) {
        log_printf("no info\n");
        return 0;
    }
    if(e->ee_origin == SO_EE_ORIGIN_LOCAL)
        log_printf("%2d?: %-32s ", ctl->ttl, "[LOCALHOST]");
    else if(e->ee_origin == SO_EE_ORIGIN_ICMP6 ||
            e->ee_origin == SO_EE_ORIGIN_ICMP) {
        char abuf[NI_MAXHOST];
        struct sockaddr *sa = (struct sockaddr *) (e + 1);
        socklen_t salen;

        if(sndhops > 0)
            log_printf("%2d:  ", sndhops);
        else
            log_printf("%2d?: ", ctl->ttl);

        switch (sa->sa_family) {
        case AF_INET6:
            salen = sizeof(struct sockaddr_in6);
            break;
        case AF_INET:
            salen = sizeof(struct sockaddr_in);
            break;
        default:
            salen = 0;
        }

        if(ctl->no_resolve || ctl->show_both)
                {
            if(getnameinfo(sa, salen, abuf, sizeof(abuf), NULL, 0,
            NI_NUMERICHOST))
                strcpy(abuf, "???");
            ctl->his[slot].host_namea = strdup(abuf);
        } else
            abuf[0] = 0;

        if(!ctl->no_resolve || ctl->show_both)
                {
            fflush(stdout);
            if(getnameinfo(sa, salen, hnamebuf, sizeof hnamebuf, NULL, 0,
            getnameinfo_flags))
                strcpy(hnamebuf, "???");
            ctl->his[slot].host_nameb = strdup(hnamebuf);
        } else
            hnamebuf[0] = 0;

        if(ctl->no_resolve) {
            print_host(ctl, abuf, hnamebuf);
        }
        else {
            print_host(ctl, hnamebuf, abuf);
        }
    }

    if(rettv) {
        struct timeval res;

        timersub(&tv, rettv, &res);
        if(deltatv)
            memcpy(deltatv, &res, sizeof(struct timeval));
        log_printf("%3ld.%03ldms ", res.tv_sec * 1000 + res.tv_usec / 1000, res.tv_usec % 1000);
        if(broken_router)
            log_printf("(This broken router returned corrupted payload) ");
    }

    if(rethops <= 64)
        rethops = 65 - rethops;
    else if(rethops <= 128)
        rethops = 129 - rethops;
    else
        rethops = 256 - rethops;

    //log_printf("ERROR=%d ", e->ee_errno);
    switch (e->ee_errno) {
    case ETIMEDOUT:
        log_printf("\n");
        break;
    case EMSGSIZE:
        log_printf("pmtu %d\n", e->ee_info);
        ctl->mtu = e->ee_info;
        progress = ctl->mtu;
        break;
    case ECONNREFUSED:
        log_printf("reached\n");
        ctl->hops_to = sndhops < 0 ? ctl->ttl : sndhops;
        ctl->hops_from = rethops;
        return 0;
    case EPROTO:
        log_printf("!P\n");
        return 0;
    case EHOSTUNREACH:
        if((e->ee_origin == SO_EE_ORIGIN_ICMP &&
                e->ee_type == ICMP_TIME_EXCEEDED &&
                e->ee_code == ICMP_EXC_TTL) ||
                (e->ee_origin == SO_EE_ORIGIN_ICMP6 &&
                        e->ee_type == ICMPV6_TIME_EXCEED &&
                        e->ee_code == ICMPV6_EXC_HOPLIMIT)) {
            if(rethops >= 0) {
                if(sndhops >= 0 && rethops != sndhops)
                    log_printf("asymm %2d ", rethops);
                else if(sndhops < 0 && rethops != ctl->ttl)
                    log_printf("asymm %2d ", rethops);
            }
            //log_printf("hops=->%2d, <-%2d  ", sndhops, rethops);
            log_printf("\n");
            break;
        }
        printf("!H\n");
        return 0;
    case ENETUNREACH:
        log_printf("!N\n");
        return 0;
    case EACCES:
        log_printf("!A\n");
        return 0;
    default:
        printf("\n");
        errno = e->ee_errno;
        perror("NET ERROR");
        return 0;
    }
    goto restart;
    return 0;
}

static int probe_ttl(struct run_state * const ctl)
{
    int i;
    struct probehdr *hdr = ctl->pktbuf;

    memset(ctl->pktbuf, 0, ctl->mtu);
    restart:
    for(i = 0; i < MAX_PROBES; i++) {
        int res;

        hdr->ttl = ctl->ttl;
        switch (ctl->ai->ai_family) {
        case AF_INET6:
            ((struct sockaddr_in6 *) &ctl->target)->sin6_port =
                    htons(ctl->base_port + ctl->hisptr);
            break;
        case AF_INET:
            ((struct sockaddr_in *) &ctl->target)->sin_port =
                    htons(ctl->base_port + ctl->hisptr);
            break;
        }
        gettimeofday(&hdr->tv, NULL);
        ctl->his[ctl->hisptr].hops = ctl->ttl;
        ctl->his[ctl->hisptr].sendtime = hdr->tv;
        if(sendto(ctl->socket_fd, ctl->pktbuf, ctl->mtu - ctl->overhead, 0,
                (struct sockaddr *) &ctl->target, ctl->targetlen) > 0)
            break;
        res = recverr(ctl);
        ctl->his[ctl->hisptr].hops = 0;
        if(res == 0)
            return 0;
        if(res > 0)
            goto restart;
    }
    ctl->hisptr = (ctl->hisptr + 1) & (HIS_ARRAY_SIZE - 1);

    if(i < MAX_PROBES) {
        data_wait(ctl);
        if(recv(ctl->socket_fd, ctl->pktbuf, ctl->mtu, MSG_DONTWAIT) > 0) {
            log_printf("%2d?: reply received 8)\n", ctl->ttl);
            return 0;
        }
        return recverr(ctl);
    }

    log_printf("%2d:  send failed\n", ctl->ttl);
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
            "\nUsage\n"
                    "  tracepath [options] <destination>\n"
                    "\nOptions:\n"
                    "  -4             use IPv4\n"
                    "  -6             use IPv6\n"
                    "  -b             print both name and ip\n"
                    "  -l <length>    use packet <length>\n"
                    "  -m <hops>      use maximum <hops>\n"
                    "  -n             no dns name resolution\n"
                    "  -p <port>      use destination <port>\n"
                    "  -V             print version and exit\n"
                    "  <destination>  dns name or ip address\n"
                    "\nFor more details see tracepath(8).\n");
    exit(-1);
}

int tracepath_main(int argc, char **argv, struct run_state *ctl)
{
    int ret = -1;
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP,
#ifdef USE_IDN
            .ai_flags = AI_IDN | AI_CANONNAME,
#endif
        };
    struct addrinfo *result;
    int ch;
    int status;
    int on;
    char *p;
    char pbuf[NI_MAXSERV];

#ifdef USE_IDN
    setlocale(LC_ALL, "");
#endif

    /* Support being called using `tracepath4` or `tracepath6` symlinks */
    if(argv[0][strlen(argv[0]) - 1] == '4')
        hints.ai_family = AF_INET;
    else if(argv[0][strlen(argv[0]) - 1] == '6')
        hints.ai_family = AF_INET6;

    while((ch = getopt(argc, argv, "46nbh?l:m:p:V")) != EOF) {
        switch (ch) {
        case '4':
            if(hints.ai_family == AF_INET6) {
                fprintf(stderr,
                        "tracepath: Only one -4 or -6 option may be specified\n");
                return -1; //exit(2);
            }
            hints.ai_family = AF_INET;
            break;
        case '6':
            if(hints.ai_family == AF_INET) {
                fprintf(stderr,
                        "tracepath: Only one -4 or -6 option may be specified\n");
                return -1; //exit(2);
            }
            hints.ai_family = AF_INET6;
            break;
        case 'n':
            ctl->no_resolve = 1;
            break;
        case 'b':
            ctl->show_both = 1;
            break;
        case 'l':
            if((ctl->mtu = atoi(optarg)) <= ctl->overhead) {
                fprintf(stderr,
                        "Error: pktlen must be > %d and <= %d.\n",
                        ctl->overhead, INT_MAX);
                return -1; //exit(1);
            }
            break;
        case 'm':
            ctl->max_hops = atoi(optarg);
            if(ctl->max_hops < 0 || ctl->max_hops > MAX_HOPS_LIMIT) {
                fprintf(stderr,
                        "Error: max hops must be 0 .. %d (inclusive).\n",
                        MAX_HOPS_LIMIT);
                return -1; //exit(1);
            }
            break;
        case 'p':
            ctl->base_port = atoi(optarg);
            break;
        case 'V':
            printf(IPUTILS_VERSION("tracepath"));
            return 0;
        default:
            usage();
        }
    }

    argc -= optind;
    argv += optind;
    optind = 0;

    if(argc != 1)
        usage();

    /* Backward compatibility */
    if(!ctl->base_port) {
        p = strchr(argv[0], '/');
        if(p) {
            *p = 0;
            ctl->base_port = atoi(p + 1);
        } else
            ctl->base_port = DEFAULT_BASEPORT;
    }
    sprintf(pbuf, "%u", ctl->base_port);

    status = getaddrinfo(argv[0], pbuf, &hints, &result);
    if(status) {
        fprintf(stderr, "tracepath: %s: %s\n", argv[0],
                gai_strerror(status));
        return -EADDRNOTAVAIL;//exit(1);
    }

    for(ctl->ai = result; ctl->ai; ctl->ai = ctl->ai->ai_next) {
        if(ctl->ai->ai_family != AF_INET6 && ctl->ai->ai_family != AF_INET)
            continue;
        ctl->socket_fd = socket(ctl->ai->ai_family, ctl->ai->ai_socktype, ctl->ai->ai_protocol);
        if(ctl->socket_fd < 0)
            continue;
        memcpy(&ctl->target, ctl->ai->ai_addr, ctl->ai->ai_addrlen);
        ctl->targetlen = ctl->ai->ai_addrlen;
        break;
    }
    if(ctl->socket_fd < 0) {
        perror("socket/connect");
        return -ESOCKTNOSUPPORT;//exit(1);
    }

    switch (ctl->ai->ai_family) {
    case AF_INET6:
        ctl->overhead = DEFAULT_OVERHEAD_IPV6;
        if(!ctl->mtu)
            ctl->mtu = DEFAULT_MTU_IPV6;
        if(ctl->mtu <= ctl->overhead)
            goto pktlen_error;

        on = IPV6_PMTUDISC_DO;
        if(setsockopt(ctl->socket_fd, SOL_IPV6, IPV6_MTU_DISCOVER, &on, sizeof(on)) &&
                (on = IPV6_PMTUDISC_DO, setsockopt(ctl->socket_fd, SOL_IPV6,
                IPV6_MTU_DISCOVER, &on, sizeof(on)))) {
            perror("IPV6_MTU_DISCOVER");
            return -2;//exit(1);
        }
        on = 1;
        if(setsockopt(ctl->socket_fd, SOL_IPV6, IPV6_RECVERR, &on, sizeof(on))) {
            perror("IPV6_RECVERR");
            return -3;//exit(1);
        }
        if(setsockopt(ctl->socket_fd, SOL_IPV6, IPV6_HOPLIMIT, &on, sizeof(on))
                #ifdef IPV6_RECVHOPLIMIT
                && setsockopt(ctl->socket_fd, SOL_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on))
                        #endif
                        ) {
            perror("IPV6_HOPLIMIT");
            return -4;//exit(1);
        }
        if(!IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 * )&ctl->target)->sin6_addr)))
            break;
        ctl->mapped = 1;
        /*FALLTHROUGH*/
    case AF_INET:
        ctl->overhead = DEFAULT_OVERHEAD_IPV4;
        if(!ctl->mtu)
            ctl->mtu = DEFAULT_MTU_IPV4;
        if(ctl->mtu <= ctl->overhead)
            goto pktlen_error;

        on = IP_PMTUDISC_DO;
        if(setsockopt(ctl->socket_fd, SOL_IP, IP_MTU_DISCOVER, &on, sizeof(on))) {
            perror("IP_MTU_DISCOVER");
            return -5;//exit(1);
        }
        on = 1;
        if(setsockopt(ctl->socket_fd, SOL_IP, IP_RECVERR, &on, sizeof(on))) {
            perror("IP_RECVERR");
            return -6;//exit(1);
        }
        if(setsockopt(ctl->socket_fd, SOL_IP, IP_RECVTTL, &on, sizeof(on))) {
            perror("IP_RECVTTL");
            return -7;//exit(1);
        }
    }

    ctl->pktbuf = malloc(ctl->mtu);
    if(!ctl->pktbuf) {
        perror("malloc");
        return -8; //exit(1);
    }

//    struct sockaddr sa;
//    int salen6 = sizeof(struct sockaddr_in6);
//    int salen = sizeof(struct sockaddr_in);
    char target_ip[NI_MAXHOST];
    char *target_name = argv[0];
    memset(&target_ip, 0, sizeof(target_ip));
    getnameinfo((struct sockaddr *) &ctl->target, ctl->targetlen, target_ip, sizeof(target_ip), NULL, 0,
    NI_NUMERICHOST);
    log_printf("START target_name=%s target_ip=%s\n", target_name, target_ip);

    for(ctl->ttl = 1; ctl->ttl <= ctl->max_hops; ctl->ttl++) {
        int res;
        int i;

        on = ctl->ttl;
        switch (ctl->ai->ai_family) {
        case AF_INET6:
            if(setsockopt(ctl->socket_fd, SOL_IPV6, IPV6_UNICAST_HOPS, &on, sizeof(on))) {
                perror("IPV6_UNICAST_HOPS");
                return -9; //exit(1);
            }
            if(!ctl->mapped)
                break;
            /*FALLTHROUGH*/
        case AF_INET:
            if(setsockopt(ctl->socket_fd, SOL_IP, IP_TTL, &on, sizeof(on))) {
                perror("IP_TTL");
                return -10; //exit(1);
            }
        }

        restart:
        for(i = 0; i < 2; i++) {
            int old_mtu;

            old_mtu = ctl->mtu;
            res = probe_ttl(ctl);
            if(ctl->mtu != old_mtu)
                goto restart;
            if(res == 0)
                goto done;
            if(res > 0)
                break;
        }
        // if already find need name, make ret>=0 and break
        {
            int i = ctl->hisptr - 1;
            //for(int i = 0; i < MAX_HOPS_DEFAULT; i++)
            {
                char *host_namea = (ctl->his[i].host_namea);
                char *host_nameb = (ctl->his[i].host_nameb);
                if(host_namea) {
                    if(!strcmp(host_namea, target_name) || !strcmp(host_namea, target_ip)) {
                        ctl->ttl = ctl->max_hops;
                        ret = i;
                        break;
                    }
                }
                if(host_nameb) {
                    if(!strcmp(host_nameb, target_name) || !strcmp(host_nameb, target_ip)) {
                        ctl->ttl = ctl->max_hops;
                        ret = i;
                        break;
                    }
                }
            }
        }
        if(res < 0)
            log_printf("%2d:  no reply\n", ctl->ttl);
    }
    log_printf("     Too many hops: pmtu %d\n", ctl->mtu);

    done:
    freeaddrinfo(result);

    log_printf("     Resume: pmtu %d ", ctl->mtu);
    if(ctl->hops_to >= 0)
            {
        ret = ctl->hisptr - 1;
        log_printf("hops %d ", ctl->hops_to);
    }
    if(ctl->hops_from >= 0)
        log_printf("back %d ", ctl->hops_from);
    log_printf("\n");
    return ret; //exit(0);

    pktlen_error:
    fprintf(stderr, "Error: pktlen must be > %d and <= %d\n",
            ctl->overhead, INT_MAX);
    return -1; //exit(1);
}

/**
 * Tracepath host
 *
 * @addr[in] host name or IP address
 * @hops[out] hops count
 * @time_usec[out] latency in microseconds
 * @return 0 Ok, -1 error
 */
int tracepath_util(const char *addr, int *hops, int *time_usec)
{
    int type = 4; // 4 or 6
    int total_hops = 0;
    long int total_time_usec = 0; // latency in microseconds
    int argc = 4;
    const char *argv[argc];
    if(type != 4)
        argv[0] = "tracepath6";
    else
        argv[0] = "tracepath4";
    argv[1] = "-b"; // print both name and ip
    argv[2] = "-m 26"; // -n -m 16
    argv[3] = addr;
    struct run_state ctl = {
        .max_hops = MAX_HOPS_DEFAULT,
        .hops_to = -1,
        .hops_from = -1,
        0
    };
    int ret = tracepath_main(argc, (char**) argv, &ctl);
    for(int i = 0; i < MAX_HOPS_DEFAULT; i++) {
        DAP_DELETE(ctl.his[i].host_namea);
        DAP_DELETE(ctl.his[i].host_nameb);
    }
    if(ret >= 0)
            {
        struct timeval *deltatime = &(ctl.his[ret].deltatime);
        total_hops = ctl.his[ret].hop;
        total_time_usec = deltatime->tv_sec * 1000000 + deltatime->tv_usec;
    }
    else
        for(int i = 0; i < MAX_HOPS_DEFAULT; i++) {
            struct timeval *deltatime = &(ctl.his[i].deltatime);
            if(ctl.his[i].hop) { //if(!ctl.his[i].hops && (deltatime->tv_sec > 0 || deltatime->tv_usec > 0)) {
                total_hops = ctl.his[i].hop;
                total_time_usec = deltatime->tv_sec * 1000000 + deltatime->tv_usec;
            }
            /*if(ctl.his[i].hop > 0)
             {
             char *host_name = (ctl.his[i].host_name) ? ctl.his[i].host_name : "-";
             printf("%d %d: %s %ld\n", ctl.his[i].hops, ctl.his[i].hop, host_name,
             deltatime->tv_sec * 1000000 + deltatime->tv_usec);
             }*/
        }
    if(hops) {
        *hops = total_hops;
    }
    if(time_usec) {
        *time_usec = total_time_usec;
    }
    return (ret >= 0) ? 0 : ret;

}

