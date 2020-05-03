/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 *			P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 * Bugs -
 *	More statistics could always be gathered.
 *	If kernel does not support non-raw ICMP sockets,
 *	this program has to run SUID to ROOT or with
 *	net_cap_raw enabled.
 */

#include "ping.h"

#include <assert.h>
#include <netinet/ip_icmp.h>
#include <ifaddrs.h>
#include <math.h>
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "iputils.h"

#ifndef ICMP_FILTER
#define ICMP_FILTER	1
struct icmp_filter {
    uint32_t data;
};
#endif

ping_func_set_st ping4_func_set = {
    .send_probe = ping4_send_probe,
    .receive_error_msg = ping4_receive_error_msg,
    .parse_reply = ping4_parse_reply,
    .install_filter = ping4_install_filter
};

#define	MAXIPLEN	60
#define	MAXICMPLEN	76
#define	NROUTES		9		/* number of record route slots */
#define TOS_MAX		255		/* 8-bit TOS field */

/*
static int ts_type;
static int nroute = 0;
static uint32_t route[10];

static struct sockaddr_in whereto; // who to ping
static int optlen = 0;
static int settos = 0; // Set TOS, Precendence or other QOS options

static int broadcast_pings = 0;

static struct sockaddr_in source = { .sin_family = AF_INET };
char *device;
int pmtudisc = -1;
*/

static void pr_options(ping_handle_t *a_ping_handle, unsigned char * cp, int hlen);
static void pr_iph(ping_handle_t *a_ping_handle, struct iphdr *ip);
static unsigned short in_cksum(const unsigned short *addr, int len, unsigned short salt);
static void pr_icmph(ping_handle_t *a_ping_handle, uint8_t type, uint8_t code, uint32_t info, struct icmphdr *icp);
static int parsetos(char *str);
static int parseflow(char *str);

ping_handle_t* ping_handle_create(void)
{
    ping_handle_t *lping = DAP_NEW_Z(ping_handle_t);
    lping->source.sin_family = AF_INET;
    lping->pmtudisc = -1;

    lping->ping_common.interval = 1000; // interval between packets (msec)
    lping->ping_common.preload = 1;
    lping->ping_common.lingertime = MAXWAIT * 1000;


    lping->ping_common.confirm_flag = MSG_CONFIRM;

    lping->ping_common.tmin = LONG_MAX; // minimum round trip time
    lping->ping_common.pipesize = -1;

    lping->ping_common.datalen = DEFDATALEN;

    lping->ping_common.screen_width = INT_MAX;

#ifdef HAVE_LIBCAP
    lping->ping_common.cap_raw = CAP_NET_RAW;
    lping->ping_common.cap_admin = CAP_NET_ADMIN;
#endif

    return lping;
}

static void create_socket(ping_handle_t *a_ping_handle, socket_st *sock, int family, int socktype, int protocol, int requisite)
{
    int do_fallback = 0;

    errno = 0;

    assert(sock->fd == -1);
    assert(socktype == SOCK_DGRAM || socktype == SOCK_RAW);

    /* Attempt to create a ping socket if requested. Attempt to create a raw
     * socket otherwise or as a fallback. Well known errno values follow.
     *
     * 1) EACCES
     *
     * Kernel returns EACCES for all ping socket creation attempts when the
     * user isn't allowed to use ping socket. A range of group ids is
     * configured using the `net.ipv4.ping_group_range` sysctl. Fallback
     * to raw socket is necessary.
     *
     * Kernel returns EACCES for all raw socket creation attempts when the
     * process doesn't have the `CAP_NET_RAW` capability.
     *
     * 2) EAFNOSUPPORT
     *
     * Kernel returns EAFNOSUPPORT for IPv6 ping or raw socket creation
     * attempts when run with IPv6 support disabled (e.g. via `ipv6.disable=1`
     * kernel command-line option.
     *
     * https://github.com/iputils/iputils/issues/32
     *
     * OpenVZ 2.6.32-042stab113.11 and possibly other older kernels return
     * EAFNOSUPPORT for all IPv4 ping socket creation attempts due to lack
     * of support in the kernel. Fallback to raw socket is necessary.
     *
     * https://github.com/iputils/iputils/issues/54
     *
     * 3) EPROTONOSUPPORT
     *
     * OpenVZ 2.6.32-042stab113.11 and possibly other older kernels return
     * EPROTONOSUPPORT for all IPv6 ping socket creation attempts due to lack
     * of support in the kernel [1]. Debian 9.5 based container with kernel 4.10
     * returns EPROTONOSUPPORT also for IPv4 [2]. Fallback to raw socket is
     * necessary.
     *
     * [1] https://github.com/iputils/iputils/issues/54
     * [2] https://github.com/iputils/iputils/issues/129
     */
    if(socktype == SOCK_DGRAM)
        sock->fd = socket(family, socktype, protocol);

    /* Kernel doesn't support ping sockets. */
    if(sock->fd == -1 && errno == EAFNOSUPPORT && family == AF_INET)
        do_fallback = 1;
    if(sock->fd == -1 && errno == EPROTONOSUPPORT)
        do_fallback = 1;

    /* User is not allowed to use ping sockets. */
    if(sock->fd == -1 && errno == EACCES)
        do_fallback = 1;

    if(socktype == SOCK_RAW || do_fallback) {
        socktype = SOCK_RAW;
        sock->fd = socket(family, SOCK_RAW, protocol);
    }

    if(sock->fd == -1) {
        /* Report error related to disabled IPv6 only when IPv6 also failed or in
         * verbose mode. Report other errors always.
         */
        if((errno == EAFNOSUPPORT && socktype == AF_INET6) || (a_ping_handle->ping_common.options & F_VERBOSE) || requisite)
            error(0, errno, "socket");
        if(requisite)
            exit(2);
    } else
        sock->socktype = socktype;
}

static void set_socket_option(socket_st *sock, int level, int optname, const void *optval, socklen_t olen)
{
    if(sock->fd == -1)
        return;

    if(setsockopt(sock->fd, level, optname, optval, olen) == -1)
        error(2, errno, "setsockopt");
}

/* Much like stdtod(3, but will fails if str is not valid number. */
static double ping_strtod(const char *str, const char *err_msg)
{
    double num;
    char *end = NULL;

    if(str == NULL || *str == '\0')
        goto err;
    errno = 0;
#ifdef USE_IDN
    setlocale(LC_ALL, "C");
#endif
    num = strtod(str, &end);
#ifdef USE_IDN
    setlocale(LC_ALL, "");
#endif
    if(errno || str == end || (end && *end))
        goto err;
    switch (fpclassify(num)) {
    case FP_NORMAL:
        case FP_ZERO:
        break;
    default:
        errno = ERANGE;
        goto err;
    }
    return num;
    err:
    error(2, errno, "%s: %s", err_msg, str);
    abort(); /* cannot be reached, above error() will exit */
    return 0.0;
}

static int ping_main(ping_handle_t *a_ping_handle, int argc, char **argv)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_protocol = IPPROTO_UDP, .ai_socktype = SOCK_DGRAM, .ai_flags =
    getaddrinfo_flags };
    struct addrinfo *result, *ai;
    int status;
    int ch;
    socket_st sock4 = { .fd = -1 };
    socket_st sock6 = { .fd = -1 };
    char *target;

    limit_capabilities(a_ping_handle);

#ifdef USE_IDN
    setlocale(LC_ALL, "");
    if (!strcmp(setlocale(LC_ALL, NULL), "C"))
    hints.ai_flags &= ~ AI_CANONIDN;
#endif

    /* Support being called using `ping4` or `ping6` symlinks */
    if(argv[0][strlen(argv[0]) - 1] == '4')
        hints.ai_family = AF_INET;
    else if(argv[0][strlen(argv[0]) - 1] == '6')
        hints.ai_family = AF_INET6;

    /* Parse command line options */
    while((ch = getopt(argc, argv, "h?" "4bRT:" "6F:N:" "aABc:dDfi:I:l:Lm:M:nOp:qQ:rs:S:t:UvVw:W:")) != EOF) {
        switch (ch) {
        /* IPv4 specific options */
        case '4':
            if(hints.ai_family != AF_UNSPEC)
                error(2, 0, "only one -4 or -6 option may be specified");
            hints.ai_family = AF_INET;
            break;
        case 'b':
            a_ping_handle->broadcast_pings = 1;
            break;
        case 'R':
            if(a_ping_handle->ping_common.options & F_TIMESTAMP)
                error(2, 0, "only one of -T or -R may be used");
            a_ping_handle->ping_common.options |= F_RROUTE;
            break;
        case 'T':
            if(a_ping_handle->ping_common.options & F_RROUTE)
                error(2, 0, "only one of -T or -R may be used");
            a_ping_handle->ping_common.options |= F_TIMESTAMP;
            if(strcmp(optarg, "tsonly") == 0)
                a_ping_handle->ts_type = IPOPT_TS_TSONLY;
            else if(strcmp(optarg, "tsandaddr") == 0)
                a_ping_handle->ts_type = IPOPT_TS_TSANDADDR;
            else if(strcmp(optarg, "tsprespec") == 0)
                a_ping_handle->ts_type = IPOPT_TS_PRESPEC;
            else
                error(2, 0, "invalid timestamp type: %s", optarg);
            break;
            /* IPv6 specific options */
        case '6':
            if(hints.ai_family != AF_UNSPEC)
                error(2, 0, "only one -4 or -6 option may be specified");
            hints.ai_family = AF_INET6;
            break;
        case 'F':
            flowlabel = parseflow(optarg);
            a_ping_handle->ping_common.options |= F_FLOWINFO;
            break;
        case 'N':
            if(niquery_option_handler(optarg) < 0)
                usage();
            hints.ai_socktype = SOCK_RAW;
            break;
            /* Common options */
        case 'a':
            a_ping_handle->ping_common.options |= F_AUDIBLE;
            break;
        case 'A':
            a_ping_handle->ping_common.options |= F_ADAPTIVE;
            break;
        case 'B':
            a_ping_handle->ping_common.options |= F_STRICTSOURCE;
            break;
        case 'c':
            a_ping_handle->ping_common.npackets = atoi(optarg);
            if(a_ping_handle->ping_common.npackets <= 0)
                error(2, 0, "bad number of packets to transmit: %ld", a_ping_handle->ping_common.npackets);
            break;
        case 'd':
            a_ping_handle->ping_common.options |= F_SO_DEBUG;
            break;
        case 'D':
            a_ping_handle->ping_common.options |= F_PTIMEOFDAY;
            break;
        case 'i':
            {
            double optval;

            optval = ping_strtod(optarg, "bad timing interval");
            if(isgreater(optval, (double)(INT_MAX / 1000)))
                error(2, 0, "bad timing interval: %s", optarg);
            a_ping_handle->ping_common.interval = (int) (optval * 1000);
            a_ping_handle->ping_common.options |= F_INTERVAL;
        }
            break;
        case 'I':
            /* IPv6 */
            if(strchr(optarg, ':')) {
                char *p, *addr = strdup(optarg);

                if(!addr)
                    error(2, errno, "cannot copy: %s", optarg);

                p = strchr(addr, SCOPE_DELIMITER);
                if(p) {
                    *p = '\0';
                    a_ping_handle->device = optarg + (p - addr) + 1;
                }

                if(inet_pton(AF_INET6, addr, (char*) &source6.sin6_addr) <= 0)
                    error(2, 0, "invalid source address: %s", optarg);

                a_ping_handle->ping_common.options |= F_STRICTSOURCE;

                free(addr);
            } else if(inet_pton(AF_INET, optarg, &a_ping_handle->source.sin_addr) > 0) {
                a_ping_handle->ping_common.options |= F_STRICTSOURCE;
            } else {
                a_ping_handle->device = optarg;
            }
            break;
        case 'l':
            a_ping_handle->ping_common.preload = atoi(optarg);
            if(a_ping_handle->ping_common.preload <= 0)
                error(2, 0, "bad preload value: %s, should be 1..%d", optarg, MAX_DUP_CHK);
            if(a_ping_handle->ping_common.preload > MAX_DUP_CHK)
                a_ping_handle->ping_common.preload = MAX_DUP_CHK;
            if(a_ping_handle->ping_common.uid && a_ping_handle->ping_common.preload > 3)
                error(2, 0, "cannot set preload to value greater than 3: %d", a_ping_handle->ping_common.preload);
            break;
        case 'L':
            a_ping_handle->ping_common.options |= F_NOLOOP;
            break;
        case 'm':
            {
            char *endp;
            a_ping_handle->ping_common.mark = (int) strtoul(optarg, &endp, 10);
            if(a_ping_handle->ping_common.mark < 0 || *endp != '\0')
                error(2, 0, "mark cannot be negative: %s", optarg);
            a_ping_handle->ping_common.options |= F_MARK;
            break;
        }
        case 'M':
            if(strcmp(optarg, "do") == 0)
                a_ping_handle->pmtudisc = IP_PMTUDISC_DO;
            else if(strcmp(optarg, "dont") == 0)
                a_ping_handle->pmtudisc = IP_PMTUDISC_DONT;
            else if(strcmp(optarg, "want") == 0)
                a_ping_handle->pmtudisc = IP_PMTUDISC_WANT;
            else
                error(2, 0, "invalid -M argument: %s", optarg);
            break;
        case 'n':
            a_ping_handle->ping_common.options |= F_NUMERIC;
            break;
        case 'O':
            a_ping_handle->ping_common.options |= F_OUTSTANDING;
            break;
        case 'f':
            /* avoid `getaddrinfo()` during flood */
            a_ping_handle->ping_common.options |= F_FLOOD | F_NUMERIC;
            setbuf(stdout, (char *) NULL);
            break;
        case 'p':
            a_ping_handle->ping_common.options |= F_PINGFILLED;
            fill(a_ping_handle, optarg, a_ping_handle->ping_common.outpack, sizeof(a_ping_handle->ping_common.outpack));
            break;
        case 'q':
            a_ping_handle->ping_common.options |= F_QUIET;
            break;
        case 'Q':
            a_ping_handle->settos = parsetos(optarg); /* IPv4 */
            tclass = a_ping_handle->settos; /* IPv6 */
            break;
        case 'r':
            a_ping_handle->ping_common.options |= F_SO_DONTROUTE;
            break;
        case 's':
            a_ping_handle->ping_common.datalen = atoi(optarg);
            if(a_ping_handle->ping_common.datalen < 0)
                error(2, 0, "illegal packet size: %d", a_ping_handle->ping_common.datalen);
            if(a_ping_handle->ping_common.datalen > MAXPACKET - 8)
                error(2, 0, "packet size too large: %d", a_ping_handle->ping_common.datalen);
            break;
        case 'S':
            a_ping_handle->ping_common.sndbuf = atoi(optarg);
            if(a_ping_handle->ping_common.sndbuf <= 0)
                error(2, 0, "bad sndbuf value: %s", optarg);
            break;
        case 't':
            a_ping_handle->ping_common.options |= F_TTL;
            a_ping_handle->ping_common.ttl = atoi(optarg);
            if(a_ping_handle->ping_common.ttl < 0 || a_ping_handle->ping_common.ttl > 255)
                error(2, 0, "ttl out of range: %s", optarg);
            break;
        case 'U':
            a_ping_handle->ping_common.options |= F_LATENCY;
            break;
        case 'v':
            a_ping_handle->ping_common.options |= F_VERBOSE;
            break;
        case 'V':
            printf(IPUTILS_VERSION("ping"));
            exit(0);
        case 'w':
            a_ping_handle->ping_common.deadline = atoi(optarg);
            if(a_ping_handle->ping_common.deadline < 0)
                error(2, 0, "bad wait time: %s", optarg);
            break;
        case 'W':
            {
            double optval;

            optval = ping_strtod(optarg, "bad linger time");
            if(isless(optval, 0.001) || isgreater(optval, (double)(INT_MAX / 1000)))
                error(2, 0, "bad linger time: %s", optarg);
            /* lingertime will be converted to usec later */
            a_ping_handle->ping_common.lingertime = (int) (optval * 1000);
        }
            break;
        default:
            usage();
            break;
        }
    }

    argc -= optind;
    argv += optind;
    optind = 0;

    if(!argc)
    {
        //error(1, EDESTADDRREQ, "usage error");
        return -EDESTADDRREQ;//    89  Destination address required
    }

    target = argv[argc - 1];

    /* Create sockets */
    enable_capability_raw(a_ping_handle);
    if(hints.ai_family != AF_INET6)
        create_socket(a_ping_handle, &sock4, AF_INET, hints.ai_socktype, IPPROTO_ICMP, hints.ai_family == AF_INET);
    if(hints.ai_family != AF_INET) {
        create_socket(a_ping_handle, &sock6, AF_INET6, hints.ai_socktype, IPPROTO_ICMPV6, sock4.fd == -1);
        /* This may not be needed if both protocol versions always had the same value, but
         * since I don't know that, it's better to be safe than sorry. */
        a_ping_handle->pmtudisc = a_ping_handle->pmtudisc == IP_PMTUDISC_DO ? IPV6_PMTUDISC_DO :
                                  a_ping_handle->pmtudisc == IP_PMTUDISC_DONT ? IPV6_PMTUDISC_DONT :
                                  a_ping_handle->pmtudisc == IP_PMTUDISC_WANT ? IPV6_PMTUDISC_WANT : a_ping_handle->pmtudisc;
    }
    disable_capability_raw(a_ping_handle);

    /* Limit address family on single-protocol systems */
    if(hints.ai_family == AF_UNSPEC) {
        if(sock4.fd == -1)
            hints.ai_family = AF_INET6;
        else if(sock6.fd == -1)
            hints.ai_family = AF_INET;
    }

    /* Set socket options */
    if(a_ping_handle->settos)
        set_socket_option(&sock4, IPPROTO_IP, IP_TOS, &a_ping_handle->settos, sizeof (a_ping_handle->settos));
    if(tclass)
        set_socket_option(&sock6, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof tclass);

    status = getaddrinfo(target, NULL, &hints, &result);
    if(status)
    {
        //error(2, 0, "%s: %s", target, gai_strerror(status));
        return -EADDRNOTAVAIL;//
    }

    for(ai = result; ai; ai = ai->ai_next) {
        switch (ai->ai_family) {
        case AF_INET:
            status = ping4_run(a_ping_handle, argc, argv, ai, &sock4);
            break;
        case AF_INET6:
            status = ping6_run(a_ping_handle, argc, argv, ai, &sock6);
            break;
        default:
        {
            //error(2, 0, "unknown protocol family: %d", ai->ai_family);
            return -EPFNOSUPPORT;
        }
        }

        if(status == 0)
            break;
    }

    freeaddrinfo(result);

    return status;
}

/**
 * Send ping
 *
 * @type for ipv4=4, for ipv6=6
 * @addr host name or IP address
 * @count number of packets to transmit
 * @return ping time in microsecond or -1 if error
 */
int ping_util_common(ping_handle_t *a_ping_handle, int type, const char *addr, int count)
{

    /*
     rights for /bin/ping: -rwsr-xr-x 1 root root
     current parametr:
     # sysctl net.ipv4.ping_group_range
     net.ipv4.ping_group_range = 1   0
     Need change range for other users:
     # sysctl net.ipv4.ping_group_range="1 65000"
     */
    a_ping_handle->ping_common.tsum = a_ping_handle->ping_common.ntransmitted = a_ping_handle->ping_common.nreceived = exiting = 0;
    int argc = 3;
    const char *argv[argc];
    if(type != 4)
        argv[0] = "ping6";
    else
        argv[0] = "ping4";
    argv[1] = dap_strdup_printf("-c%d", count);
    argv[2] = addr;
    int status = ping_main(a_ping_handle, argc, (char**) argv);
    DAP_DELETE((char*) argv[1]);
    if(a_ping_handle->ping_common.ntransmitted >= 1 && a_ping_handle->ping_common.nreceived >= 1)
        return a_ping_handle->ping_common.tsum;
    return status;
}

/**
 * Send ping for ipv4
 *
 * @addr host name or IP address
 * @count number of packets to transmit
 * @return ping time in microsecond or -1 if error
 */
int ping_util(ping_handle_t *a_ping_handle, const char *addr, int count)
{
    return ping_util_common(a_ping_handle, 4, addr, count);
}

/**
 * Send ping for ipv6
 *
 * @addr host name or IP address
 * @count number of packets to transmit
 * @return ping time in microsecond or -1 if error
 */
int ping_util6(ping_handle_t *a_ping_handle, const char *addr, int count)
{
    return ping_util_common(a_ping_handle, 6, addr, count);
}

int ping4_run(ping_handle_t *a_ping_handle, int argc, char **argv, struct addrinfo *ai, socket_st *sock)
{
    static const struct addrinfo hints = { .ai_family = AF_INET, .ai_protocol = IPPROTO_UDP, .ai_flags =
    getaddrinfo_flags };
    int hold, packlen;
    unsigned char *packet;
    char *target;
    char hnamebuf[NI_MAXHOST];
    unsigned char rspace[3 + 4 * NROUTES + 1]; /* record route space */
    uint32_t *tmp_rspace;

    if(argc > 1) {
        if(a_ping_handle->ping_common.options & F_RROUTE)
            usage();
        else if(a_ping_handle->ping_common.options & F_TIMESTAMP) {
            if(a_ping_handle->ts_type != IPOPT_TS_PRESPEC)
                usage();
            if(argc > 5)
                usage();
        } else {
            if(argc > 10)
                usage();
            a_ping_handle->ping_common.options |= F_SOURCEROUTE;
        }
    }
    while(argc > 0) {
        target = *argv;

        memset((char *) &a_ping_handle->whereto, 0, sizeof(a_ping_handle->whereto));
        a_ping_handle->whereto.sin_family = AF_INET;
        if(inet_aton(target, &a_ping_handle->whereto.sin_addr) == 1) {
            a_ping_handle->ping_common.hostname = target;
            if(argc == 1)
                a_ping_handle->ping_common.options |= F_NUMERIC;
        } else {
            struct addrinfo *result = NULL;
            int status;

            if(argc > 1 || !ai) {
                status = getaddrinfo(target, NULL, &hints, &result);
                if(status)
                    error(2, 0, "%s: %s", target, gai_strerror(status));
                ai = result;
            }

            memcpy(&a_ping_handle->whereto, ai->ai_addr, sizeof (a_ping_handle->whereto));
            memset(hnamebuf, 0, sizeof hnamebuf);
            if(ai->ai_canonname)
                strncpy(hnamebuf, ai->ai_canonname, sizeof hnamebuf - 1);
            a_ping_handle->ping_common.hostname = hnamebuf;

            if(result)
                freeaddrinfo(result);
        }
        if(argc > 1)
            a_ping_handle->route[a_ping_handle->nroute++] = a_ping_handle->whereto.sin_addr.s_addr;
        argc--;
        argv++;
    }

    if(a_ping_handle->source.sin_addr.s_addr == 0) {
        socklen_t alen;
        struct sockaddr_in dst = a_ping_handle->whereto;
        int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);

        if(probe_fd < 0)
            error(2, errno, "socket");
        if(a_ping_handle->device) {
            struct ifreq ifr;
            int i;
            int fds[2] = { probe_fd, sock->fd };

            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, a_ping_handle->device, IFNAMSIZ - 1);

            for(i = 0; i < 2; i++) {
                int fd = fds[i];
                int rc;
                int errno_save;

                enable_capability_raw(a_ping_handle);
                rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, a_ping_handle->device, strlen(a_ping_handle->device) + 1);
                errno_save = errno;
                disable_capability_raw(a_ping_handle);

                if(rc == -1) {
                    if(IN_MULTICAST(ntohl(dst.sin_addr.s_addr))) {
                        struct ip_mreqn imr;
                        if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
                            error(2, 0, "unknown iface: %s", a_ping_handle->device);
                        memset(&imr, 0, sizeof(imr));
                        imr.imr_ifindex = ifr.ifr_ifindex;
                        if(setsockopt(fd, SOL_IP, IP_MULTICAST_IF, &imr, sizeof(imr)) == -1)
                            error(2, errno, "IP_MULTICAST_IF");
                    } else
                        error(2, errno_save, "SO_BINDTODEVICE %s", a_ping_handle->device);
                }
            }
        }

        if(a_ping_handle->settos &&
                setsockopt(probe_fd, IPPROTO_IP, IP_TOS, (char *) &a_ping_handle->settos, sizeof(int)) < 0)
            error(0, errno, "warning: QOS sockopts");

        dst.sin_port = htons(1025);
        if(a_ping_handle->nroute)
            dst.sin_addr.s_addr = a_ping_handle->route[0];
        if(connect(probe_fd, (struct sockaddr*) &dst, sizeof(dst)) == -1) {
            if(errno == EACCES) {
                if(a_ping_handle->broadcast_pings == 0)
                    error(2, 0,
                            "Do you want to ping broadcast? Then -b. If not, check your local firewall rules");
                fprintf(stderr, "WARNING: pinging broadcast address\n");
                if(setsockopt(probe_fd, SOL_SOCKET, SO_BROADCAST,
                        &a_ping_handle->broadcast_pings, sizeof(a_ping_handle->broadcast_pings)) < 0)
                    error(2, errno, "cannot set broadcasting");
                if(connect(probe_fd, (struct sockaddr*) &dst, sizeof(dst)) == -1)
                    error(2, errno, "connect");
            } else
                error(2, errno, "connect");
        }
        alen = sizeof(a_ping_handle->source);
        if(getsockname(probe_fd, (struct sockaddr*) &a_ping_handle->source, &alen) == -1)
            error(2, errno, "getsockname");
        a_ping_handle->source.sin_port = 0;

        if(a_ping_handle->device) {
            struct ifaddrs *ifa0, *ifa;
            int ret;

            ret = getifaddrs(&ifa0);
            if(ret)
                error(2, errno, "gatifaddrs failed");
            for(ifa = ifa0; ifa; ifa = ifa->ifa_next) {
                if(!ifa->ifa_name || !ifa->ifa_addr ||
                        ifa->ifa_addr->sa_family != AF_INET)
                    continue;
                if(!strcmp(ifa->ifa_name, a_ping_handle->device) &&
                        !memcmp(&((struct sockaddr_in *) ifa->ifa_addr)->sin_addr,
                                &a_ping_handle->source.sin_addr, sizeof(a_ping_handle->source.sin_addr)))
                    break;
            }
            if(ifa && !memcmp(&((struct sockaddr_in *) ifa->ifa_addr)->sin_addr,
                    &dst.sin_addr, sizeof(a_ping_handle->source.sin_addr))) {
                enable_capability_raw(a_ping_handle);
                setsockopt(sock->fd, SOL_SOCKET, SO_BINDTODEVICE, "", 0);
                disable_capability_raw(a_ping_handle);
            }
            freeifaddrs(ifa0);
            if(!ifa)
                error(0, 0, "Warning: source address might be selected on device other than: %s", a_ping_handle->device);
        }
        close(probe_fd);
    }
    while(0)
        ;

    if(a_ping_handle->whereto.sin_addr.s_addr == 0)
        a_ping_handle->whereto.sin_addr.s_addr = a_ping_handle->source.sin_addr.s_addr;

    if(a_ping_handle->device) {
        struct ifreq ifr;

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, a_ping_handle->device, IFNAMSIZ - 1);
        if(ioctl(sock->fd, SIOCGIFINDEX, &ifr) < 0)
            error(2, 0, "unknown iface: %s", a_ping_handle->device);
    }

    if(a_ping_handle->broadcast_pings || IN_MULTICAST(ntohl(a_ping_handle->whereto.sin_addr.s_addr))) {
        if(a_ping_handle->ping_common.uid) {
            if(a_ping_handle->ping_common.interval < 1000)
                error(2, 0, "broadcast ping with too short interval: %d", a_ping_handle->ping_common.interval);
            if(a_ping_handle->pmtudisc >= 0 && a_ping_handle->pmtudisc != IP_PMTUDISC_DO)
                error(2, 0, "broadcast ping does not fragment");
        }
        if(a_ping_handle->pmtudisc < 0)
            a_ping_handle->pmtudisc = IP_PMTUDISC_DO;
    }

    if(a_ping_handle->pmtudisc >= 0) {
        if(setsockopt(sock->fd, SOL_IP, IP_MTU_DISCOVER, &a_ping_handle->pmtudisc, sizeof (a_ping_handle->pmtudisc)) == -1)
            error(2, errno, "IP_MTU_DISCOVER");
    }

    if((a_ping_handle->ping_common.options & F_STRICTSOURCE) &&
            bind(sock->fd, (struct sockaddr *) &a_ping_handle->source, sizeof (a_ping_handle->source)) == -1)
        error(2, errno, "bind");

    if(sock->socktype == SOCK_RAW) {
        struct icmp_filter filt;
        filt.data = ~((1 << ICMP_SOURCE_QUENCH) |
                (1 << ICMP_DEST_UNREACH) |
                (1 << ICMP_TIME_EXCEEDED) |
                (1 << ICMP_PARAMETERPROB) |
                (1 << ICMP_REDIRECT) |
                (1 << ICMP_ECHOREPLY));
        if(setsockopt(sock->fd, SOL_RAW, ICMP_FILTER, &filt, sizeof filt) == -1)
            error(0, errno, "WARNING: setsockopt(ICMP_FILTER)");
    }

    hold = 1;
    if(setsockopt(sock->fd, SOL_IP, IP_RECVERR, &hold, sizeof hold))
        error(0, 0, "WARNING: your kernel is veeery old. No problems.");

    if(sock->socktype == SOCK_DGRAM) {
        if(setsockopt(sock->fd, SOL_IP, IP_RECVTTL, &hold, sizeof hold))
            error(0, errno, "WARNING: setsockopt(IP_RECVTTL)");
        if(setsockopt(sock->fd, SOL_IP, IP_RETOPTS, &hold, sizeof hold))
            error(0, errno, "WARNING: setsockopt(IP_RETOPTS)");
    }

    /* record route option */
    if(a_ping_handle->ping_common.options & F_RROUTE) {
        memset(rspace, 0, sizeof(rspace));
        rspace[0] = IPOPT_NOP;
        rspace[1 + IPOPT_OPTVAL] = IPOPT_RR;
        rspace[1 + IPOPT_OLEN] = sizeof(rspace) - 1;
        rspace[1 + IPOPT_OFFSET] = IPOPT_MINOFF;
        a_ping_handle->optlen = 40;
        if(setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, sizeof rspace) < 0)
            error(2, errno, "record route");
    }
    if(a_ping_handle->ping_common.options & F_TIMESTAMP) {
        memset(rspace, 0, sizeof(rspace));
        rspace[0] = IPOPT_TIMESTAMP;
        rspace[1] = (a_ping_handle->ts_type == IPOPT_TS_TSONLY ? 40 : 36);
        rspace[2] = 5;
        rspace[3] = a_ping_handle->ts_type;
        if(a_ping_handle->ts_type == IPOPT_TS_PRESPEC) {
            int i;
            rspace[1] = 4 + a_ping_handle->nroute * 8;
            for(i = 0; i < a_ping_handle->nroute; i++) {
                tmp_rspace = (uint32_t*) &rspace[4 + i * 8];
                *tmp_rspace = a_ping_handle->route[i];
            }
        }
        if(setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
            rspace[3] = 2;
            if(setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0)
                error(2, errno, "ts option");
        }
        a_ping_handle->optlen = 40;
    }
    if(a_ping_handle->ping_common.options & F_SOURCEROUTE) {
        int i;
        memset(rspace, 0, sizeof(rspace));
        rspace[0] = IPOPT_NOOP;
        rspace[1 + IPOPT_OPTVAL] = (a_ping_handle->ping_common.options & F_SO_DONTROUTE) ? IPOPT_SSRR
                                                                :
                                                                IPOPT_LSRR;
        rspace[1 + IPOPT_OLEN] = 3 + a_ping_handle->nroute * 4;
        rspace[1 + IPOPT_OFFSET] = IPOPT_MINOFF;
        for(i = 0; i < a_ping_handle->nroute; i++) {
            tmp_rspace = (uint32_t*) &rspace[4 + i * 4];
            *tmp_rspace = a_ping_handle->route[i];
        }

        if(setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, 4 + a_ping_handle->nroute * 4) < 0)
            error(2, errno, "record route");
        a_ping_handle->optlen = 40;
    }

    /* Estimate memory eaten by single packet. It is rough estimate.
     * Actually, for small datalen's it depends on kernel side a lot. */
    hold = a_ping_handle->ping_common.datalen + 8;
    hold += ((hold + 511) / 512) * (a_ping_handle->optlen + 20 + 16 + 64 + 160);
    sock_setbufs(a_ping_handle, sock, hold);

    if(a_ping_handle->broadcast_pings) {
        if(setsockopt(sock->fd, SOL_SOCKET, SO_BROADCAST, &a_ping_handle->broadcast_pings, sizeof (a_ping_handle->broadcast_pings)) < 0)
            error(2, errno, "cannot set broadcasting");
    }

    if(a_ping_handle->ping_common.options & F_NOLOOP) {
        int loop = 0;
        if(setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof loop) == -1)
            error(2, errno, "cannot disable multicast loopback");
    }
    if(a_ping_handle->ping_common.options & F_TTL) {
        int ittl = a_ping_handle->ping_common.ttl;
        if(setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_TTL, &a_ping_handle->ping_common.ttl, sizeof (a_ping_handle->ping_common.ttl)) == -1)
            error(2, errno, "cannot set multicast time-to-live");
        if(setsockopt(sock->fd, IPPROTO_IP, IP_TTL, &ittl, sizeof ittl) == -1)
            error(2, errno, "cannot set unicast time-to-live");
    }

    if(a_ping_handle->ping_common.datalen > 0xFFFF - 8 - a_ping_handle->optlen - 20)
        error(2, 0, "packet size %d is too large. Maximum is %d",
                a_ping_handle->ping_common.datalen, 0xFFFF - 8 - 20 - a_ping_handle->optlen);

    if(a_ping_handle->ping_common.datalen >= (int) sizeof(struct timeval)) /* can we time transfer */
        a_ping_handle->ping_common.timing = 1;
    packlen = a_ping_handle->ping_common.datalen + MAXIPLEN + MAXICMPLEN;
    if(!(packet = (unsigned char *) malloc((unsigned int) packlen)))
        error(2, errno, "memory allocation failed");

//printf("PING %s (%s) ", hostname, inet_ntoa(whereto.sin_addr));
    if(a_ping_handle->device || (a_ping_handle->ping_common.options & F_STRICTSOURCE))
        printf("from %s %s: ", inet_ntoa(a_ping_handle->source.sin_addr), a_ping_handle->device ? a_ping_handle->device : "");
//printf("%d(%d) bytes of data.\n", datalen, datalen + 8 + optlen + 20);

    setup(a_ping_handle, sock);
    log_printf("main_loop start %s (%s)\n", a_ping_handle->ping_common.hostname, inet_ntoa(a_ping_handle->whereto.sin_addr));
    main_loop(a_ping_handle, &ping4_func_set, sock, packet, packlen);
    log_printf("main_loop end\n");
    return 0;
}

int ping4_receive_error_msg(ping_handle_t *a_ping_handle, socket_st *sock)
{
    ssize_t res;
    char cbuf[512];
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsgh;
    struct sock_extended_err *e;
    struct icmphdr icmph;
    struct sockaddr_in target;
    int net_errors = 0;
    int local_errors = 0;
    int saved_errno = errno;

    iov.iov_base = &icmph;
    iov.iov_len = sizeof(icmph);
    msg.msg_name = (void*) &target;
    msg.msg_namelen = sizeof(target);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    if(!sock)
        return net_errors;
    res = recvmsg(sock->fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
    if(res < 0)
        goto out;

    e = NULL;
    for(cmsgh = CMSG_FIRSTHDR(&msg); cmsgh; cmsgh = CMSG_NXTHDR(&msg, cmsgh)) {
        if(cmsgh->cmsg_level == SOL_IP) {
            if(cmsgh->cmsg_type == IP_RECVERR)
                e = (struct sock_extended_err *) CMSG_DATA(cmsgh);
        }
    }
    if(e == NULL)
        abort();

    if(e->ee_origin == SO_EE_ORIGIN_LOCAL) {
        local_errors++;
        if(a_ping_handle->ping_common.options & F_QUIET)
            goto out;
        if(a_ping_handle->ping_common.options & F_FLOOD)
            write_stdout("E", 1);
        else if(e->ee_errno != EMSGSIZE)
            error(0, 0, "local error: %s", strerror(e->ee_errno));
        else
            error(0, 0, "local error: message too long, mtu=%u", e->ee_info);
        a_ping_handle->ping_common.nerrors++;
    } else if(e->ee_origin == SO_EE_ORIGIN_ICMP) {
        struct sockaddr_in *sin = (struct sockaddr_in*) (e + 1);

        if(res < (ssize_t) sizeof(icmph) ||
                target.sin_addr.s_addr != a_ping_handle->whereto.sin_addr.s_addr ||
                icmph.type != ICMP_ECHO ||
                !is_ours(a_ping_handle, sock, icmph.un.echo.id)) {
            /* Not our error, not an error at all. Clear. */
            saved_errno = 0;
            goto out;
        }

        acknowledge(a_ping_handle, ntohs(icmph.un.echo.sequence));

        net_errors++;
        a_ping_handle->ping_common.nerrors++;
        if(a_ping_handle->ping_common.options & F_QUIET)
            goto out;
        if(a_ping_handle->ping_common.options & F_FLOOD) {
            write_stdout("\bE", 2);
        } else {
            print_timestamp(a_ping_handle);
            printf("From %s icmp_seq=%u ", pr_addr(a_ping_handle, sin, sizeof *sin), ntohs(icmph.un.echo.sequence));
            pr_icmph(a_ping_handle, e->ee_type, e->ee_code, e->ee_info, NULL);
            fflush(stdout);
        }
    }

    out:
    errno = saved_errno;
    return net_errors ? net_errors : -local_errors;
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int ping4_send_probe(ping_handle_t *a_ping_handle, socket_st *sock, void *packet, unsigned packet_size __attribute__((__unused__)))
{
    struct icmphdr *icp;
    int cc;
    int i;

    icp = (struct icmphdr *) packet;
    icp->type = ICMP_ECHO;
    icp->code = 0;
    icp->checksum = 0;
    icp->un.echo.sequence = htons(a_ping_handle->ping_common.ntransmitted + 1);
    icp->un.echo.id = a_ping_handle->ping_common.ident; /* ID */

    rcvd_clear(a_ping_handle, a_ping_handle->ping_common.ntransmitted + 1);

    if(a_ping_handle->ping_common.timing) {
        if(a_ping_handle->ping_common.options & F_LATENCY) {
            struct timeval tmp_tv;
            gettimeofday(&tmp_tv, NULL);
            memcpy(icp + 1, &tmp_tv, sizeof(tmp_tv));
        } else {
            memset(icp + 1, 0, sizeof(struct timeval));
        }
    }

    cc = a_ping_handle->ping_common.datalen + 8; /* skips ICMP portion */

    /* compute ICMP checksum here */
    icp->checksum = in_cksum((unsigned short *) icp, cc, 0);

    if(a_ping_handle->ping_common.timing && !(a_ping_handle->ping_common.options & F_LATENCY)) {
        struct timeval tmp_tv;
        gettimeofday(&tmp_tv, NULL);
        memcpy(icp + 1, &tmp_tv, sizeof(tmp_tv));
        icp->checksum = in_cksum((unsigned short *) &tmp_tv, sizeof(tmp_tv), ~icp->checksum);
    }

    i = sendto(sock->fd, icp, cc, 0, (struct sockaddr*) &a_ping_handle->whereto, sizeof(a_ping_handle->whereto));
    //log_printf("**sendto(fd=%d,icp=0x%x,cc=%d)=%d\n",sock->fd,&icp,cc,i);
    return (cc == i ? 0 : i);
}

/*
 * parse_reply --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
static
void pr_echo_reply(uint8_t *_icp, int len __attribute__((__unused__)))
{
    struct icmphdr *icp = (struct icmphdr *) _icp;
    log_printf(" icmp_seq=%u", ntohs(icp->un.echo.sequence));
}

int
ping4_parse_reply(ping_handle_t *a_ping_handle, struct socket_st *sock, struct msghdr *msg, int cc, void *addr, struct timeval *tv)
{
    struct sockaddr_in *from = addr;
    uint8_t *buf = msg->msg_iov->iov_base;
    struct icmphdr *icp;
    struct iphdr *ip;
    int hlen;
    int csfailed;
    struct cmsghdr *cmsgh;
    int reply_ttl;
    uint8_t *opts, *tmp_ttl;
    int olen;

    /* Check the IP header */
    ip = (struct iphdr *) buf;
    if(sock->socktype == SOCK_RAW) {
        hlen = ip->ihl * 4;
        if(cc < hlen + 8 || ip->ihl < 5) {
            if(a_ping_handle->ping_common.options & F_VERBOSE)
                error(0, 0, "packet too short (%d bytes) from %s", cc,
                        pr_addr(a_ping_handle, from, sizeof *from));
            return 1;
        }
        reply_ttl = ip->ttl;
        opts = buf + sizeof(struct iphdr);
        olen = hlen - sizeof(struct iphdr);
    } else {
        hlen = 0;
        reply_ttl = 0;
        opts = buf;
        olen = 0;
        for(cmsgh = CMSG_FIRSTHDR(msg); cmsgh; cmsgh = CMSG_NXTHDR(msg, cmsgh)) {
            if(cmsgh->cmsg_level != SOL_IP)
                continue;
            if(cmsgh->cmsg_type == IP_TTL) {
                if(cmsgh->cmsg_len < sizeof(int))
                    continue;
                tmp_ttl = (uint8_t *) CMSG_DATA(cmsgh);
                reply_ttl = (int) *tmp_ttl;
            } else if(cmsgh->cmsg_type == IP_RETOPTS) {
                opts = (uint8_t *) CMSG_DATA(cmsgh);
                olen = cmsgh->cmsg_len;
            }
        }
    }

    /* Now the ICMP part */
    cc -= hlen;
    icp = (struct icmphdr *) (buf + hlen);
    csfailed = in_cksum((unsigned short *) icp, cc, 0);

    if(icp->type == ICMP_ECHOREPLY) {
        //log_printf("in ping4_parse_reply00\n");
        if(!is_ours(a_ping_handle, sock, icp->un.echo.id))
            return 1; /* 'Twas not our ECHO */
        if(!contains_pattern_in_payload(a_ping_handle, (uint8_t*) (icp + 1)))
            return 1; /* 'Twas really not our ECHO */
        if(gather_statistics(a_ping_handle, (uint8_t*) icp, sizeof(*icp), cc,
                ntohs(icp->un.echo.sequence),
                reply_ttl, 0, tv, pr_addr(a_ping_handle, from, sizeof *from),
                pr_echo_reply)) {
            fflush(stdout);
            return 0;
        }
        //log_printf("in ping4_parse_reply01\n");
    } else {
        /* We fall here when a redirect or source quench arrived. */
        switch (icp->type) {
        case ICMP_ECHO:
            /* MUST NOT */
            return 1;
        case ICMP_SOURCE_QUENCH:
            case ICMP_REDIRECT:
            case ICMP_DEST_UNREACH:
            case ICMP_TIME_EXCEEDED:
            case ICMP_PARAMETERPROB:
            {
            struct iphdr * iph = (struct iphdr *) (&icp[1]);
            struct icmphdr *icp1 = (struct icmphdr*) ((unsigned char *) iph + iph->ihl * 4);
            int error_pkt;
            if(cc < (int) (8 + sizeof(struct iphdr) + 8) ||
                    cc < 8 + iph->ihl * 4 + 8)
                return 1;
            if(icp1->type != ICMP_ECHO ||
                    iph->daddr != a_ping_handle->whereto.sin_addr.s_addr ||
                    !is_ours(a_ping_handle, sock, icp1->un.echo.id))
                return 1;
            error_pkt = (icp->type != ICMP_REDIRECT &&
                    icp->type != ICMP_SOURCE_QUENCH);
            if(error_pkt) {
                acknowledge(a_ping_handle, ntohs(icp1->un.echo.sequence));
                return 0;
            }
            if(a_ping_handle->ping_common.options & (F_QUIET | F_FLOOD))
                return 1;
            print_timestamp(a_ping_handle);
            log_printf("From %s: icmp_seq=%u ",
                    pr_addr(a_ping_handle, from, sizeof *from),
                    ntohs(icp1->un.echo.sequence));
            if(csfailed)
                log_printf("(BAD CHECKSUM)");
            pr_icmph(a_ping_handle, icp->type, icp->code, ntohl(icp->un.gateway), icp);
            return 1;
        }
        default:
            /* MUST NOT */
            break;
        }
        if((a_ping_handle->ping_common.options & F_FLOOD) && !(a_ping_handle->ping_common.options & (F_VERBOSE | F_QUIET))) {
            if(!csfailed)
                write_stdout("!E", 2);
            else
                write_stdout("!EC", 3);
            return 0;
        }
        if(!(a_ping_handle->ping_common.options & F_VERBOSE) || a_ping_handle->ping_common.uid)
            return 0;
        if(a_ping_handle->ping_common.options & F_PTIMEOFDAY) {
            struct timeval recv_time;
            gettimeofday(&recv_time, NULL);
            log_printf("%lu.%06lu ", (unsigned long) recv_time.tv_sec, (unsigned long) recv_time.tv_usec);
        }
        printf("From %s: ", pr_addr(a_ping_handle, from, sizeof *from));
        if(csfailed) {
            log_printf("(BAD CHECKSUM)\n");
            return 0;
        }
        pr_icmph(a_ping_handle, icp->type, icp->code, ntohl(icp->un.gateway), icp);
        return 0;
    }

    if(a_ping_handle->ping_common.options & F_AUDIBLE) {
        log_printf("\a"); //putchar('\a');
        if(a_ping_handle->ping_common.options & F_FLOOD)
            fflush(stdout);
    }
    if(!(a_ping_handle->ping_common.options & F_FLOOD)) {
        pr_options(a_ping_handle, opts, olen + sizeof(struct iphdr));

        log_printf("\n"); //putchar('\n');
        fflush(stdout);
    }
    return 0;
}

#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

unsigned short
in_cksum(const unsigned short *addr, int len, unsigned short csum)
{
    int nleft = len;
    const unsigned short *w = addr;
    unsigned short answer;
    int sum = csum;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while(nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if(nleft == 1)
        sum += ODDBYTE(*(unsigned char * )w); /* le16toh() may be unavailable on old systems */

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16); /* add carry */
    answer = ~sum; /* truncate to 16 bits */
    return (answer);
}

/*
 * pr_icmph --
 *	Print a descriptive string about an ICMP header.
 */
void pr_icmph(ping_handle_t *a_ping_handle, uint8_t type, uint8_t code, uint32_t info, struct icmphdr *icp)
{
    switch (type) {
    case ICMP_ECHOREPLY:
        printf("Echo Reply\n");
        /* XXX ID + Seq + Data */
        break;
    case ICMP_DEST_UNREACH:
        switch (code) {
        case ICMP_NET_UNREACH:
            printf("Destination Net Unreachable\n");
            break;
        case ICMP_HOST_UNREACH:
            printf("Destination Host Unreachable\n");
            break;
        case ICMP_PROT_UNREACH:
            printf("Destination Protocol Unreachable\n");
            break;
        case ICMP_PORT_UNREACH:
            printf("Destination Port Unreachable\n");
            break;
        case ICMP_FRAG_NEEDED:
            printf("Frag needed and DF set (mtu = %u)\n", info);
            break;
        case ICMP_SR_FAILED:
            printf("Source Route Failed\n");
            break;
        case ICMP_NET_UNKNOWN:
            printf("Destination Net Unknown\n");
            break;
        case ICMP_HOST_UNKNOWN:
            printf("Destination Host Unknown\n");
            break;
        case ICMP_HOST_ISOLATED:
            printf("Source Host Isolated\n");
            break;
        case ICMP_NET_ANO:
            printf("Destination Net Prohibited\n");
            break;
        case ICMP_HOST_ANO:
            printf("Destination Host Prohibited\n");
            break;
        case ICMP_NET_UNR_TOS:
            printf("Destination Net Unreachable for Type of Service\n");
            break;
        case ICMP_HOST_UNR_TOS:
            printf("Destination Host Unreachable for Type of Service\n");
            break;
        case ICMP_PKT_FILTERED:
            printf("Packet filtered\n");
            break;
        case ICMP_PREC_VIOLATION:
            printf("Precedence Violation\n");
            break;
        case ICMP_PREC_CUTOFF:
            printf("Precedence Cutoff\n");
            break;
        default:
            printf("Dest Unreachable, Bad Code: %d\n", code);
            break;
        }
        if(icp && (a_ping_handle->ping_common.options & F_VERBOSE))
            pr_iph(a_ping_handle, (struct iphdr*) (icp + 1));
        break;
    case ICMP_SOURCE_QUENCH:
        printf("Source Quench\n");
        if(icp && (a_ping_handle->ping_common.options & F_VERBOSE))
            pr_iph(a_ping_handle, (struct iphdr*) (icp + 1));
        break;
    case ICMP_REDIRECT:
        switch (code) {
        case ICMP_REDIR_NET:
            printf("Redirect Network");
            break;
        case ICMP_REDIR_HOST:
            printf("Redirect Host");
            break;
        case ICMP_REDIR_NETTOS:
            printf("Redirect Type of Service and Network");
            break;
        case ICMP_REDIR_HOSTTOS:
            printf("Redirect Type of Service and Host");
            break;
        default:
            printf("Redirect, Bad Code: %d", code);
            break;
        }
        {
            struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { icp ? icp->un.gateway : info } };

            printf("(New nexthop: %s)\n", pr_addr(a_ping_handle, &sin, sizeof sin));
        }
        if(icp && (a_ping_handle->ping_common.options & F_VERBOSE))
            pr_iph(a_ping_handle, (struct iphdr*) (icp + 1));
        break;
    case ICMP_ECHO:
        printf("Echo Request\n");
        /* XXX ID + Seq + Data */
        break;
    case ICMP_TIME_EXCEEDED:
        switch (code) {
        case ICMP_EXC_TTL:
            printf("Time to live exceeded\n");
            break;
        case ICMP_EXC_FRAGTIME:
            printf("Frag reassembly time exceeded\n");
            break;
        default:
            printf("Time exceeded, Bad Code: %d\n", code);
            break;
        }
        if(icp && (a_ping_handle->ping_common.options & F_VERBOSE))
            pr_iph(a_ping_handle, (struct iphdr*) (icp + 1));
        break;
    case ICMP_PARAMETERPROB:
        printf("Parameter problem: pointer = %u\n", icp ? (ntohl(icp->un.gateway) >> 24) : info);
        if(icp && (a_ping_handle->ping_common.options & F_VERBOSE))
            pr_iph(a_ping_handle, (struct iphdr*) (icp + 1));
        break;
    case ICMP_TIMESTAMP:
        printf("Timestamp\n");
        /* XXX ID + Seq + 3 timestamps */
        break;
    case ICMP_TIMESTAMPREPLY:
        printf("Timestamp Reply\n");
        /* XXX ID + Seq + 3 timestamps */
        break;
    case ICMP_INFO_REQUEST:
        printf("Information Request\n");
        /* XXX ID + Seq */
        break;
    case ICMP_INFO_REPLY:
        printf("Information Reply\n");
        /* XXX ID + Seq */
        break;
#ifdef ICMP_MASKREQ
    case ICMP_MASKREQ:
        printf("Address Mask Request\n");
        break;
#endif
#ifdef ICMP_MASKREPLY
    case ICMP_MASKREPLY:
        printf("Address Mask Reply\n");
        break;
#endif
    default:
        printf("Bad ICMP type: %d\n", type);
    }
}

void pr_options(ping_handle_t *a_ping_handle, unsigned char * cp, int hlen)
{
    int i, j;
    int olen, totlen;
    unsigned char * optptr;
    static int old_rrlen;
    static char old_rr[MAX_IPOPTLEN];

    totlen = hlen - sizeof(struct iphdr);
    optptr = cp;

    while(totlen > 0) {
        if(*optptr == IPOPT_EOL)
            break;
        if(*optptr == IPOPT_NOP) {
            totlen--;
            optptr++;
            printf("\nNOP");
            continue;
        }
        cp = optptr;
        olen = optptr[1];
        if(olen < 2 || olen > totlen)
            break;

        switch (*cp) {
        case IPOPT_SSRR:
            case IPOPT_LSRR:
            printf("\n%cSRR: ", *cp == IPOPT_SSRR ? 'S' : 'L');
            j = *++cp;
            cp++;
            if(j > IPOPT_MINOFF) {
                for(;;) {
                    uint32_t address;
                    memcpy(&address, cp, 4);
                    cp += 4;
                    if(address == 0)
                        printf("\t0.0.0.0");
                    else {
                        struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { address } };

                        printf("\t%s", pr_addr(a_ping_handle, &sin, sizeof sin));
                    }
                    j -= 4;
                    putchar('\n');
                    if(j <= IPOPT_MINOFF)
                        break;
                }
            }
            break;
        case IPOPT_RR:
            j = *++cp; /* get length */
            i = *++cp; /* and pointer */
            if(i > j)
                i = j;
            i -= IPOPT_MINOFF;
            if(i <= 0)
                break;
            if(i == old_rrlen
                    && !memcmp(cp, old_rr, i)
                    && !(a_ping_handle->ping_common.options & F_FLOOD)) {
                printf("\t(same route)");
                break;
            }
            old_rrlen = i;
            memcpy(old_rr, (char *) cp, i);
            printf("\nRR: ");
            cp++;
            for(;;) {
                uint32_t address;
                memcpy(&address, cp, 4);
                cp += 4;
                if(address == 0)
                    printf("\t0.0.0.0");
                else {
                    struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { address } };

                    printf("\t%s", pr_addr(a_ping_handle, &sin, sizeof sin));
                }
                i -= 4;
                putchar('\n');
                if(i <= 0)
                    break;
            }
            break;
        case IPOPT_TS:
            {
            int stdtime = 0, nonstdtime = 0;
            uint8_t flags;
            j = *++cp; /* get length */
            i = *++cp; /* and pointer */
            if(i > j)
                i = j;
            i -= 5;
            if(i <= 0)
                break;
            flags = *++cp;
            printf("\nTS: ");
            cp++;
            for(;;) {
                long l;

                if((flags & 0xF) != IPOPT_TS_TSONLY) {
                    uint32_t address;
                    memcpy(&address, cp, 4);
                    cp += 4;
                    if(address == 0)
                        printf("\t0.0.0.0");
                    else {
                        struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { address } };

                        printf("\t%s", pr_addr(a_ping_handle, &sin, sizeof sin));
                    }
                    i -= 4;
                    if(i <= 0)
                        break;
                }
                l = *cp++;
                l = (l << 8) + *cp++;
                l = (l << 8) + *cp++;
                l = (l << 8) + *cp++;

                if(l & 0x80000000) {
                    if(nonstdtime == 0)
                        printf("\t%ld absolute not-standard", l & 0x7fffffff);
                    else
                        printf("\t%ld not-standard", (l & 0x7fffffff) - nonstdtime);
                    nonstdtime = l & 0x7fffffff;
                } else {
                    if(stdtime == 0)
                        printf("\t%ld absolute", l);
                    else
                        printf("\t%ld", l - stdtime);
                    stdtime = l;
                }
                i -= 4;
                putchar('\n');
                if(i <= 0)
                    break;
            }
            if(flags >> 4)
                printf("Unrecorded hops: %d\n", flags >> 4);
            break;
        }
        default:
            printf("\nunknown option %x", *cp);
            break;
        }
        totlen -= olen;
        optptr += olen;
    }
}

/*
 * pr_iph --
 *	Print an IP header with options.
 */
void pr_iph(ping_handle_t *a_ping_handle, struct iphdr *ip)
{
    int hlen;
    unsigned char *cp;

    hlen = ip->ihl << 2;
    cp = (unsigned char *) ip + 20; /* point to options */

    printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n");
    printf(" %1x  %1x  %02x %04x %04x",
            ip->version, ip->ihl, ip->tos, ip->tot_len, ip->id);
    printf("   %1x %04x", ((ip->frag_off) & 0xe000) >> 13,
            (ip->frag_off) & 0x1fff);
    printf("  %02x  %02x %04x", ip->ttl, ip->protocol, ip->check);
    printf(" %s ", inet_ntoa(*(struct in_addr *) &ip->saddr));
    printf(" %s ", inet_ntoa(*(struct in_addr *) &ip->daddr));
    printf("\n");
    pr_options(a_ping_handle, cp, hlen);
}

/*
 * pr_addr --
 *
 * Return an ascii host address optionally with a hostname.
 */
char *
pr_addr(ping_handle_t *a_ping_handle, void *sa, socklen_t salen)
{
    static char buffer[4096] = "";
    static struct sockaddr_storage last_sa = { 0, { 0 }, 0 };
    static socklen_t last_salen = 0;
    char name[NI_MAXHOST] = "";
    char address[NI_MAXHOST] = "";

    if(salen == last_salen && !memcmp(sa, &last_sa, salen))
        return buffer;

    memcpy(&last_sa, sa, (last_salen = salen));

    a_ping_handle->ping_common.in_pr_addr = !setjmp(a_ping_handle->ping_common.pr_addr_jmp);

    getnameinfo(sa, salen, address, sizeof address, NULL, 0, getnameinfo_flags | NI_NUMERICHOST);
    if(!exiting && !(a_ping_handle->ping_common.options & F_NUMERIC))
        getnameinfo(sa, salen, name, sizeof name, NULL, 0, getnameinfo_flags);

    if(*name)
        snprintf(buffer, sizeof buffer, "%s (%s)", name, address);
    else
        snprintf(buffer, sizeof buffer, "%s", address);

    a_ping_handle->ping_common.in_pr_addr = 0;

    return (buffer);
}

/* Set Type of Service (TOS) and other Quality of Service relating bits */
int parsetos(char *str)
{
    const char *cp;
    int tos;
    char *ep;

    /* handle both hex and decimal values */
    if(str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        cp = str + 2;
        tos = (int) strtol(cp, &ep, 16);
    } else
        tos = (int) strtol(str, &ep, 10);

    /* doesn't look like decimal or hex, eh? */
    if(*ep != '\0')
        error(2, 0, "bad TOS value: %s", str);

    if(tos > TOS_MAX)
        error(2, 0, "the decimal value of TOS bits must be in range 0-255: %d", tos);
    return (tos);
}

int parseflow(char *str)
{
    const char *cp;
    unsigned long val;
    char *ep;

    /* handle both hex and decimal values */
    if(str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        cp = str + 2;
        val = (int) strtoul(cp, &ep, 16);
    } else
        val = (int) strtoul(str, &ep, 10);

    /* doesn't look like decimal or hex, eh? */
    if(*ep != '\0')
        error(2, 0, "bad value for flowinfo: %s", str);

    if(val & ~IPV6_FLOWINFO_FLOWLABEL)
        error(2, 0, "flow value is greater than 20 bits: %s", str);
    return (val);
}

void ping4_install_filter(ping_handle_t *a_ping_handle, socket_st *sock)
{
    static int once;
    static struct sock_filter insns[] = {
    BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 0), /* Skip IP header. F..g BSD... Look into ping6. */
    BPF_STMT(BPF_LD|BPF_H|BPF_IND, 4), /* Load icmp echo ident */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0xAAAA, 0, 1), /* Ours? */
    BPF_STMT(BPF_RET|BPF_K, ~0U), /* Yes, it passes. */
    BPF_STMT(BPF_LD|BPF_B|BPF_IND, 0), /* Load icmp type */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ICMP_ECHOREPLY, 1, 0), /* Echo? */
    BPF_STMT(BPF_RET|BPF_K, 0xFFFFFFF), /* No. It passes. */
    BPF_STMT(BPF_RET|BPF_K, 0) /* Echo with wrong ident. Reject. */
    };
    static struct sock_fprog filter = {
        sizeof insns / sizeof(insns[0]),
        insns
    };

    if(once)
        return;
    once = 1;

    /* Patch bpflet for current identifier. */
    insns[2] = (struct sock_filter )BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, htons(a_ping_handle->ping_common.ident), 0, 1);

    if(setsockopt(sock->fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)))
        error(0, errno, "WARNING: failed to install socket filter");
}
