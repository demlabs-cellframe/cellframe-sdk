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

#include "ping.h"

#ifndef HZ
#define HZ sysconf(_SC_CLK_TCK)
#endif

/*
int options;

int mark;
int sndbuf;
int ttl;
int rtt;
int rtt_addend;
uint16_t acked;

unsigned char outpack[MAXPACKET];
struct rcvd_table rcvd_tbl;

// counters
long npackets; // max packets to transmit
long nreceived; // # of packets we got back
long nrepeats; // number of duplicates
long ntransmitted; // sequence # for outbound packets = #sent
long nchecksum; // replies with bad checksum
long nerrors; // icmp errors
int interval = 1000; // interval between packets (msec)
int preload = 1;
int deadline = 0; // time to die
int lingertime = MAXWAIT * 1000;
struct timeval start_time, cur_time;
int confirm = 0;
volatile int in_pr_addr = 0; // pr_addr() is executing
jmp_buf pr_addr_jmp;
*/

volatile int exiting;
volatile int status_snapshot;

/* Stupid workarounds for bugs/missing functionality in older linuces.
 * confirm_flag fixes refusing service of kernels without MSG_CONFIRM.
 * i.e. for linux-2.2 */
/*

int confirm_flag = MSG_CONFIRM;

// timing
int timing; // flag to do timing
long tmin = LONG_MAX; // minimum round trip time
long tmax; // maximum round trip time
*/
/* Message for rpm maintainers: have _shame_. If you want
 * to fix something send the patch to me for sanity checking.
 * "sparcfix" patch is a complete non-sense, apparenly the person
 * prepared it was stoned.
 */
/*
long long tsum; // sum of all times, for doing average
long long tsum2;
int pipesize = -1;

int datalen = DEFDATALEN;

char *hostname;
int uid;
uid_t euid;
int ident; // process id to identify our packets

static int screen_width = INT_MAX;

#ifdef HAVE_LIBCAP
static cap_value_t cap_raw = CAP_NET_RAW;
static cap_value_t cap_admin = CAP_NET_ADMIN;
#endif
*/

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof(a[0]))


void usage(void)
{
    fprintf(stderr,
            "\nUsage\n"
                    "  ping [options] <destination>\n"
                    "\nOptions:\n"
                    "  <destination>      dns name or ip address\n"
                    "  -a                 use audible ping\n"
                    "  -A                 use adaptive ping\n"
                    "  -B                 sticky source address\n"
                    "  -c <count>         stop after <count> replies\n"
                    "  -D                 print timestamps\n"
                    "  -d                 use SO_DEBUG socket option\n"
                    "  -f                 flood ping\n"
                    "  -h                 print help and exit\n"
                    "  -I <interface>     either interface name or address\n"
                    "  -i <interval>      seconds between sending each packet\n"
                    "  -L                 suppress loopback of multicast packets\n"
                    "  -l <preload>       send <preload> number of packages while waiting replies\n"
                    "  -m <mark>          tag the packets going out\n"
                    "  -M <pmtud opt>     define mtu discovery, can be one of <do|dont|want>\n"
                    "  -n                 no dns name resolution\n"
                    "  -O                 report outstanding replies\n"
                    "  -p <pattern>       contents of padding byte\n"
                    "  -q                 quiet output\n"
                    "  -Q <tclass>        use quality of service <tclass> bits\n"
                    "  -s <size>          use <size> as number of data bytes to be sent\n"
                    "  -S <size>          use <size> as SO_SNDBUF socket option value\n"
                    "  -t <ttl>           define time to live\n"
                    "  -U                 print user-to-user latency\n"
                    "  -v                 verbose output\n"
                    "  -V                 print version and exit\n"
                    "  -w <deadline>      reply wait <deadline> in seconds\n"
                    "  -W <timeout>       time to wait for response\n"
                    "\nIPv4 options:\n"
                    "  -4                 use IPv4\n"
                    "  -b                 allow pinging broadcast\n"
                    "  -R                 record route\n"
                    "  -T <timestamp>     define timestamp, can be one of <tsonly|tsandaddr|tsprespec>\n"
                    "\nIPv6 options:\n"
                    "  -6                 use IPv6\n"
                    "  -F <flowlabel>     define flow label, default is random\n"
                    "  -N <nodeinfo opt>  use icmp6 node info query, try <help> as argument\n"
                    "\nFor more details see ping(8).\n"
            );
    //exit(2);
    exit(2);
}

void limit_capabilities(ping_handle_t *a_ping_handle)
{
#ifdef HAVE_LIBCAP
    cap_t cap_cur_p;
    cap_t cap_p;
    cap_flag_value_t cap_ok;

    cap_cur_p = cap_get_proc();
    if (!cap_cur_p)
    error(-1, errno, "cap_get_proc");
    cap_p = cap_init();
    if (!cap_p)
    error(-1, errno, "cap_init");
    cap_ok = CAP_CLEAR;
    cap_get_flag(cap_cur_p, CAP_NET_ADMIN, CAP_PERMITTED, &cap_ok);
    if (cap_ok != CAP_CLEAR)
    cap_set_flag(cap_p, CAP_PERMITTED, 1, &cap_admin, CAP_SET);
    cap_ok = CAP_CLEAR;
    cap_get_flag(cap_cur_p, CAP_NET_RAW, CAP_PERMITTED, &cap_ok);
    if (cap_ok != CAP_CLEAR)
    cap_set_flag(cap_p, CAP_PERMITTED, 1, &cap_raw, CAP_SET);
    if (cap_set_proc(cap_p) < 0)
    error(-1, errno, "cap_set_proc");
    if (prctl(PR_SET_KEEPCAPS, 1) < 0)
    error(-1, errno, "prctl");
    if (setuid(getuid()) < 0)
    error(-1, errno, "setuid");
    if (prctl(PR_SET_KEEPCAPS, 0) < 0)
    error(-1, errno, "prctl");
    cap_free(cap_p);
    cap_free(cap_cur_p);
#endif
    a_ping_handle->ping_common.uid = getuid();
    a_ping_handle->ping_common.euid = geteuid();
#ifndef HAVE_LIBCAP
    if(seteuid(a_ping_handle->ping_common.uid))
        error(-1, errno, "setuid");
#endif
}

#ifdef HAVE_LIBCAP
int modify_capability(cap_value_t cap, cap_flag_value_t on)
{
    cap_t cap_p = cap_get_proc();
    cap_flag_value_t cap_ok;
    int rc = -1;

    if (!cap_p) {
        error(0, errno, "cap_get_proc");
        goto out;
    }

    cap_ok = CAP_CLEAR;
    cap_get_flag(cap_p, cap, CAP_PERMITTED, &cap_ok);
    if (cap_ok == CAP_CLEAR) {
        rc = on ? -1 : 0;
        goto out;
    }

    cap_set_flag(cap_p, CAP_EFFECTIVE, 1, &cap, on);

    if (cap_set_proc(cap_p) < 0) {
        error(0, errno, "cap_set_proc");
        goto out;
    }

    cap_free(cap_p);
    cap_p = NULL;

    rc = 0;
    out:
    if (cap_p)
    cap_free(cap_p);
    return rc;
}
#else
int modify_capability(ping_handle_t *a_ping_handle, int on)
{
    if(seteuid(on ? a_ping_handle->ping_common.euid : getuid())) {
        error(0, errno, "seteuid");
        return -1;
    }

    return 0;
}
#endif

void drop_capabilities(void)
{
#ifdef HAVE_LIBCAP
    cap_t cap = cap_init();
    if (cap_set_proc(cap) < 0)
    error(-1, errno, "cap_set_proc");
    cap_free(cap);
#else
    if(setuid(getuid()))
        error(-1, errno, "setuid");
#endif
}

/* Fills all the outpack, excluding ICMP header, but _including_
 * timestamp area with supplied pattern.
 */
void fill(ping_handle_t *a_ping_handle, char *patp, unsigned char *packet, unsigned packet_size)
{
    int ii, jj;
    unsigned int pat[16];
    char *cp;
    unsigned char *bp = packet + 8;

#ifdef USE_IDN
    setlocale(LC_ALL, "C");
#endif

    for(cp = patp; *cp; cp++) {
        if(!isxdigit(*cp))
            error(2, 0, "patterns must be specified as hex digits: %s", cp);
    }
    ii = sscanf(patp,
            "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
            &pat[0], &pat[1], &pat[2], &pat[3], &pat[4], &pat[5], &pat[6],
            &pat[7], &pat[8], &pat[9], &pat[10], &pat[11], &pat[12],
            &pat[13], &pat[14], &pat[15]);

    if(ii > 0) {
        unsigned kk;
        for(kk = 0; kk <= packet_size - (8 + ii); kk += ii)
            for(jj = 0; jj < ii; ++jj)
                bp[jj + kk] = pat[jj];
    }
    if(!(a_ping_handle->ping_common.options & F_QUIET)) {
        printf("PATTERN: 0x");
        for(jj = 0; jj < ii; ++jj)
            printf("%02x", bp[jj] & 0xFF);
        printf("\n");
    }

#ifdef USE_IDN
    setlocale(LC_ALL, "");
#endif
}

static void sigexit(int signo __attribute__((__unused__)))
{
    exiting = 1;
    //if(in_pr_addr)
    //    longjmp(pr_addr_jmp, 0);
}

static void sigstatus(int signo __attribute__((__unused__)))
{
    //status_snapshot = 1;
}

int __schedule_exit(ping_handle_t *a_ping_handle, int next)
{
    static unsigned long waittime;
    struct itimerval it;

    if(waittime)
        return next;

    if(a_ping_handle->ping_common.nreceived) {
        waittime = 2 * a_ping_handle->ping_common.tmax;
        if(waittime < (unsigned long) (1000 * a_ping_handle->ping_common.interval))
            waittime = 1000 * a_ping_handle->ping_common.interval;
    } else
        waittime = a_ping_handle->ping_common.lingertime * 1000;

    if(next < 0 || (unsigned long) next < waittime / 1000)
        next = waittime / 1000;

    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 0;
    it.it_value.tv_sec = waittime / 1000000;
    it.it_value.tv_usec = waittime % 1000000;
    setitimer(ITIMER_REAL, &it, NULL);
    return next;
}

static inline void update_interval(ping_handle_t *a_ping_handle)
{
    int est = a_ping_handle->ping_common.rtt ? a_ping_handle->ping_common.rtt / 8 : a_ping_handle->ping_common.interval * 1000;

    a_ping_handle->ping_common.interval = (est + a_ping_handle->ping_common.rtt_addend + 500) / 1000;
    if(a_ping_handle->ping_common.uid && a_ping_handle->ping_common.interval < MINUSERINTERVAL)
        a_ping_handle->ping_common.interval = MINUSERINTERVAL;
}

/*
 * Print timestamp
 */
void print_timestamp(ping_handle_t *a_ping_handle)
{
    if(a_ping_handle->ping_common.options & F_PTIMEOFDAY) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        printf("[%lu.%06lu] ",
                (unsigned long) tv.tv_sec, (unsigned long) tv.tv_usec);
    }
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int pinger(ping_handle_t *a_ping_handle, ping_func_set_st *fset, socket_st *sock)
{
    static int oom_count;
    static int tokens;
    int i;

    /* Have we already sent enough? If we have, return an arbitrary positive value. */
    if(exiting || (a_ping_handle->ping_common.npackets && a_ping_handle->ping_common.ntransmitted >= a_ping_handle->ping_common.npackets && !a_ping_handle->ping_common.deadline))
        return 1000;

    /* Check that packets < rate*time + preload */
    if(a_ping_handle->ping_common.cur_time.tv_sec == 0) {
        gettimeofday(&a_ping_handle->ping_common.cur_time, NULL);
        tokens = a_ping_handle->ping_common.interval * (a_ping_handle->ping_common.preload - 1);
    } else {
        long ntokens;
        struct timeval tv;

        gettimeofday(&tv, NULL);
        ntokens = (tv.tv_sec - a_ping_handle->ping_common.cur_time.tv_sec) * 1000 +
                (tv.tv_usec - a_ping_handle->ping_common.cur_time.tv_usec) / 1000;
        if(!a_ping_handle->ping_common.interval) {
            /* Case of unlimited flood is special;
             * if we see no reply, they are limited to 100pps */
            if(ntokens < MININTERVAL && in_flight(a_ping_handle) >= a_ping_handle->ping_common.preload)
                return MININTERVAL - ntokens;
        }
        ntokens += tokens;
        if(ntokens > a_ping_handle->ping_common.interval * a_ping_handle->ping_common.preload)
            ntokens = a_ping_handle->ping_common.interval * a_ping_handle->ping_common.preload;
        if(ntokens < a_ping_handle->ping_common.interval)
            return a_ping_handle->ping_common.interval - ntokens;

        a_ping_handle->ping_common.cur_time = tv;
        tokens = ntokens - a_ping_handle->ping_common.interval;
    }

    if(a_ping_handle->ping_common.options & F_OUTSTANDING) {
        if(a_ping_handle->ping_common.ntransmitted > 0 && !rcvd_test(a_ping_handle, a_ping_handle->ping_common.ntransmitted)) {
            print_timestamp(a_ping_handle);
            printf("no answer yet for icmp_seq=%lu\n", (a_ping_handle->ping_common.ntransmitted % MAX_DUP_CHK));
            fflush(stdout);
        }
    }

    resend:
    i = fset->send_probe(a_ping_handle, sock, a_ping_handle->ping_common.outpack, sizeof(a_ping_handle->ping_common.outpack));

    if(i == 0) {
        oom_count = 0;
        advance_ntransmitted(a_ping_handle);
        if(!(a_ping_handle->ping_common.options & F_QUIET) && (a_ping_handle->ping_common.options & F_FLOOD)) {
            /* Very silly, but without this output with
             * high preload or pipe size is very confusing. */
            if((a_ping_handle->ping_common.preload < a_ping_handle->ping_common.screen_width && a_ping_handle->ping_common.pipesize < a_ping_handle->ping_common.screen_width) ||
                    in_flight(a_ping_handle) < a_ping_handle->ping_common.screen_width)
                write_stdout(".", 1);
        }
        return a_ping_handle->ping_common.interval - tokens;
    }

    /* And handle various errors... */
    if(i > 0) {
        /* Apparently, it is some fatal bug. */
        abort();
    } else if(errno == ENOBUFS || errno == ENOMEM) {
        int nores_interval;

        /* Device queue overflow or OOM. Packet is not sent. */
        tokens = 0;
        /* Slowdown. This works only in adaptive mode (option -A) */
        a_ping_handle->ping_common.rtt_addend += (a_ping_handle->ping_common.rtt < 8 * 50000 ? a_ping_handle->ping_common.rtt / 8 : 50000);
        if(a_ping_handle->ping_common.options & F_ADAPTIVE)
            update_interval(a_ping_handle);
        nores_interval = SCHINT(a_ping_handle->ping_common.interval / 2);
        if(nores_interval > 500)
            nores_interval = 500;
        oom_count++;
        if(oom_count * nores_interval < a_ping_handle->ping_common.lingertime)
            return nores_interval;
        i = 0;
        /* Fall to hard error. It is to avoid complete deadlock
         * on stuck output device even when dealine was not requested.
         * Expected timings are screwed up in any case, but we will
         * exit some day. :-) */
    } else if(errno == EAGAIN) {
        /* Socket buffer is full. */
        tokens += a_ping_handle->ping_common.interval;
        return MININTERVAL;
    } else {
        if((i = fset->receive_error_msg(a_ping_handle, sock)) > 0) {
            /* An ICMP error arrived. In this case, we've received
             * an error from sendto(), but we've also received an
             * ICMP message, which means the packet did in fact
             * send in some capacity. So, in this odd case, report
             * the more specific errno as the error, and treat this
             * as a hard local error. */
            i = 0;
            goto hard_local_error;
        }
        /* Compatibility with old linuces. */
        if(i == 0 && a_ping_handle->ping_common.confirm_flag && errno == EINVAL) {
            a_ping_handle->ping_common.confirm_flag = 0;
            errno = 0;
        }
        if(!errno)
            goto resend;
    }

    hard_local_error:
    /* Hard local error. Pretend we sent packet. */
    advance_ntransmitted(a_ping_handle);

    if(i == 0 && !(a_ping_handle->ping_common.options & F_QUIET)) {
        if(a_ping_handle->ping_common.options & F_FLOOD)
            write_stdout("E", 1);
        else
            perror("ping: sendmsg");
    }
    tokens = 0;
    return SCHINT(a_ping_handle->ping_common.interval);
}

/* Set socket buffers, "alloc" is an estimate of memory taken by single packet. */

void sock_setbufs(ping_handle_t *a_ping_handle, socket_st *sock, int alloc)
{
    int rcvbuf, hold;
    socklen_t tmplen = sizeof(hold);

    if(!a_ping_handle->ping_common.sndbuf)
        a_ping_handle->ping_common.sndbuf = alloc;
    setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, (char *) &a_ping_handle->ping_common.sndbuf, sizeof(a_ping_handle->ping_common.sndbuf));

    rcvbuf = hold = alloc * a_ping_handle->ping_common.preload;
    if(hold < 65536)
        hold = 65536;
    setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, (char *) &hold, sizeof(hold));
    if(getsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, (char *) &hold, &tmplen) == 0) {
        if(hold < rcvbuf)
            error(0, 0, "WARNING: probably, rcvbuf is not enough to hold preload");
    }
}

/* Protocol independent setup and parameter checks. */

void setup(ping_handle_t *a_ping_handle, socket_st *sock)
{
    int hold;
    struct timeval tv;
    sigset_t sset;

    if((a_ping_handle->ping_common.options & F_FLOOD) && !(a_ping_handle->ping_common.options & F_INTERVAL))
        a_ping_handle->ping_common.interval = 0;

    if(a_ping_handle->ping_common.uid && a_ping_handle->ping_common.interval < MINUSERINTERVAL)
        error(2, 0, "cannot flood; minimal interval allowed for user is %dms", MINUSERINTERVAL);

    if(a_ping_handle->ping_common.interval >= INT_MAX / a_ping_handle->ping_common.preload)
        error(2, 0, "illegal preload and/or interval: %d", a_ping_handle->ping_common.interval);

    hold = 1;
    if(a_ping_handle->ping_common.options & F_SO_DEBUG)
        setsockopt(sock->fd, SOL_SOCKET, SO_DEBUG, (char *) &hold, sizeof(hold));
    if(a_ping_handle->ping_common.options & F_SO_DONTROUTE)
        setsockopt(sock->fd, SOL_SOCKET, SO_DONTROUTE, (char *) &hold, sizeof(hold));

#ifdef SO_TIMESTAMP
    if(!(a_ping_handle->ping_common.options & F_LATENCY)) {
        int on = 1;
        if(setsockopt(sock->fd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)))
            error(0, 0, "Warning: no SO_TIMESTAMP support, falling back to SIOCGSTAMP");
    }
#endif
#ifdef SO_MARK
    if(a_ping_handle->ping_common.options & F_MARK) {
        int ret;
        int errno_save;

        enable_capability_admin(a_ping_handle);
        ret = setsockopt(sock->fd, SOL_SOCKET, SO_MARK, &a_ping_handle->ping_common.mark, sizeof(a_ping_handle->ping_common.mark));
        errno_save = errno;
        disable_capability_admin(a_ping_handle);

        if(ret == -1) {
            /* we probably dont wanna exit since old kernels
             * dont support mark ..
             */
            error(0, errno_save, "Warning: Failed to set mark: %d", a_ping_handle->ping_common.mark);
        }
    }
#endif

    /* Set some SNDTIMEO to prevent blocking forever
     * on sends, when device is too slow or stalls. Just put limit
     * of one second, or "interval", if it is less.
     */
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if(a_ping_handle->ping_common.interval < 1000) {
        tv.tv_sec = 0;
        tv.tv_usec = 1000 * SCHINT(a_ping_handle->ping_common.interval);
    }
    setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (char*) &tv, sizeof(tv));

    /* Set RCVTIMEO to "interval". Note, it is just an optimization
     * allowing to avoid redundant poll(). */
    tv.tv_sec = SCHINT(a_ping_handle->ping_common.interval) / 1000;
    tv.tv_usec = 1000 * (SCHINT(a_ping_handle->ping_common.interval) % 1000);
    if(setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, (char*) &tv, sizeof(tv)))
        a_ping_handle->ping_common.options |= F_FLOOD_POLL;

    if(!(a_ping_handle->ping_common.options & F_PINGFILLED)) {
        int i;
        unsigned char *p = a_ping_handle->ping_common.outpack + 8;

        /* Do not forget about case of small datalen,
         * fill timestamp area too!
         */
        for(i = 0; i < a_ping_handle->ping_common.datalen; ++i)
            *p++ = i;
    }

    if(sock->socktype == SOCK_RAW)
        a_ping_handle->ping_common.ident = htons(getpid() & 0xFFFF);

    set_signal(SIGINT, sigexit);
    set_signal(SIGALRM, sigexit);
    set_signal(SIGQUIT, sigstatus);

    sigemptyset(&sset);
    sigprocmask(SIG_SETMASK, &sset, NULL);

    gettimeofday(&a_ping_handle->ping_common.start_time, NULL);

    if(a_ping_handle->ping_common.deadline) {
        struct itimerval it;

        it.it_interval.tv_sec = 0;
        it.it_interval.tv_usec = 0;
        it.it_value.tv_sec = a_ping_handle->ping_common.deadline;
        it.it_value.tv_usec = 0;
        setitimer(ITIMER_REAL, &it, NULL);
    }

    if(isatty(STDOUT_FILENO)) {
        struct winsize w;

        if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) {
            if(w.ws_col > 0)
                a_ping_handle->ping_common.screen_width = w.ws_col;
        }
    }
}

/*
 * Return 0 if pattern in payload point to be ptr did not match the pattern that was sent  
 */
int contains_pattern_in_payload(ping_handle_t *a_ping_handle, uint8_t *ptr)
{
    int i;
    uint8_t *cp, *dp;

    /* check the data */
    cp = ((u_char*) ptr) + sizeof(struct timeval);
    dp = &a_ping_handle->ping_common.outpack[8 + sizeof(struct timeval)];
    for(i = sizeof(struct timeval); i < a_ping_handle->ping_common.datalen; ++i, ++cp, ++dp) {
        if(*cp != *dp)
            return 0;
    }
    return 1;
}

void main_loop(ping_handle_t *a_ping_handle, ping_func_set_st *fset, socket_st *sock, uint8_t *packet, int packlen)
{
    char addrbuf[128];
    char ans_data[4096];
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *c;
    int cc;
    int next;
    int polling;
    int recv_error;

    iov.iov_base = (char *) packet;

    for(;;) {
        /* Check exit conditions. */
        if(exiting)
            break;
        if(a_ping_handle->ping_common.npackets && a_ping_handle->ping_common.nreceived + a_ping_handle->ping_common.nerrors >= a_ping_handle->ping_common.npackets)
            break;
        if(a_ping_handle->ping_common.deadline && a_ping_handle->ping_common.nerrors)
            break;
        /* Check for and do special actions. */
        if(status_snapshot)
            status(a_ping_handle);

        /* Send probes scheduled to this time. */
        do {
            next = pinger(a_ping_handle, fset, sock);
            next = schedule_exit(a_ping_handle, next);
        } while(next <= 0);

        /* "next" is time to send next probe, if positive.
         * If next<=0 send now or as soon as possible. */

        /* Technical part. Looks wicked. Could be dropped,
         * if everyone used the newest kernel. :-)
         * Its purpose is:
         * 1. Provide intervals less than resolution of scheduler.
         *    Solution: spinning.
         * 2. Avoid use of poll(), when recvmsg() can provide
         *    timed waiting (SO_RCVTIMEO). */
        polling = 0;
        recv_error = 0;
        if((a_ping_handle->ping_common.options & (F_ADAPTIVE | F_FLOOD_POLL)) || next < SCHINT(a_ping_handle->ping_common.interval)) {
            int recv_expected = in_flight(a_ping_handle);

            /* If we are here, recvmsg() is unable to wait for
             * required timeout. */
            if(1000 % HZ == 0 ? next <= 1000 / HZ : (next < INT_MAX / HZ && next * HZ <= 1000)) {
                /* Very short timeout... So, if we wait for
                 * something, we sleep for MININTERVAL.
                 * Otherwise, spin! */
                if(recv_expected) {
                    next = MININTERVAL;
                } else {
                    next = 0;
                    /* When spinning, no reasons to poll.
                     * Use nonblocking recvmsg() instead. */
                    polling = MSG_DONTWAIT;
                    /* But yield yet. */
                    sched_yield();
                }
            }

            if(!polling &&
                    ((a_ping_handle->ping_common.options & (F_ADAPTIVE | F_FLOOD_POLL)) || a_ping_handle->ping_common.interval)) {
                struct pollfd pset;
                pset.fd = sock->fd;
                pset.events = POLLIN;
                pset.revents = 0;
                if(poll(&pset, 1, next) < 1 ||
                        !(pset.revents & (POLLIN | POLLERR)))
                    continue;
                polling = MSG_DONTWAIT;
                recv_error = pset.revents & POLLERR;
            }
        }

        for(;;) {
            struct timeval *recv_timep = NULL;
            struct timeval recv_time;
            int not_ours = 0; /* Raw socket can receive messages
             * destined to other running pings. */

            iov.iov_len = packlen;
            memset(&msg, 0, sizeof(msg));
            msg.msg_name = addrbuf;
            msg.msg_namelen = sizeof(addrbuf);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ans_data;
            msg.msg_controllen = sizeof(ans_data);

            cc = recvmsg(sock->fd, &msg, polling);
            //log_printf("**recvmsg(fd=%d,msg=0x%x,polling=%d)=%d\n",sock->fd,&msg,polling,cc);
            polling = MSG_DONTWAIT;

            if(cc < 0) {
                /* If there was a POLLERR and there is no packet
                 * on the socket, try to read the error queue.
                 * Otherwise, give up.
                 */
                if((errno == EAGAIN && !recv_error) ||
                errno == EINTR)
                    break;
                recv_error = 0;
                if(!fset->receive_error_msg(a_ping_handle, sock)) {
                    if(errno) {
                        error(0, errno, "recvmsg");
                        break;
                    }
                    not_ours = 1;
                }
            } else {

#ifdef SO_TIMESTAMP
                for(c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
                    if(c->cmsg_level != SOL_SOCKET ||
                            c->cmsg_type != SO_TIMESTAMP)
                        continue;
                    if(c->cmsg_len < CMSG_LEN(sizeof(struct timeval)))
                        continue;
                    recv_timep = (struct timeval*) CMSG_DATA(c);
                }
#endif

                if((a_ping_handle->ping_common.options & F_LATENCY) || recv_timep == NULL) {
                    if((a_ping_handle->ping_common.options & F_LATENCY) ||
                            ioctl(sock->fd, SIOCGSTAMP, &recv_time))
                        gettimeofday(&recv_time, NULL);
                    recv_timep = &recv_time;
                }
                not_ours = fset->parse_reply(a_ping_handle, sock, &msg, cc, addrbuf, recv_timep);
            }

            /* See? ... someone runs another ping on this host. */
            if(not_ours && sock->socktype == SOCK_RAW)
                fset->install_filter(a_ping_handle, sock);

            /* If nothing is in flight, "break" returns us to pinger. */
            if(in_flight(a_ping_handle) == 0)
                break;

            /* Otherwise, try to recvmsg() again. recvmsg()
             * is nonblocking after the first iteration, so that
             * if nothing is queued, it will receive EAGAIN
             * and return to pinger. */
        }
    }
    // here present exit() from app
    finish(a_ping_handle);
}

int gather_statistics(ping_handle_t *a_ping_handle, uint8_t *icmph, int icmplen,
        int cc, uint16_t seq, int hops,
        int csfailed, struct timeval *tv, char *from,
        void (*pr_reply)(uint8_t *icmph, int cc))
{
    int dupflag = 0;
    long triptime = 0;
    uint8_t *ptr = icmph + icmplen;

    ++a_ping_handle->ping_common.nreceived;
    if(!csfailed)
        acknowledge(a_ping_handle, seq);

    if(a_ping_handle->ping_common.timing && cc >= (int) (8 + sizeof(struct timeval))) {
        struct timeval tmp_tv;
        memcpy(&tmp_tv, ptr, sizeof(tmp_tv));

        restamp:
        tvsub(tv, &tmp_tv);
        triptime = tv->tv_sec * 1000000 + tv->tv_usec;
        if(triptime < 0) {
            error(0, 0, "Warning: time of day goes back (%ldus), taking countermeasures", triptime);
            triptime = 0;
            if(!(a_ping_handle->ping_common.options & F_LATENCY)) {
                gettimeofday(tv, NULL);
                a_ping_handle->ping_common.options |= F_LATENCY;
                goto restamp;
            }
        }
        if(!csfailed) {
            a_ping_handle->ping_common.tsum += triptime;
            a_ping_handle->ping_common.tsum2 += (long long) triptime * (long long) triptime;
            if(triptime < a_ping_handle->ping_common.tmin)
                a_ping_handle->ping_common.tmin = triptime;
            if(triptime > a_ping_handle->ping_common.tmax)
                a_ping_handle->ping_common.tmax = triptime;
            if(!a_ping_handle->ping_common.rtt)
                a_ping_handle->ping_common.rtt = triptime * 8;
            else
                a_ping_handle->ping_common.rtt += triptime - a_ping_handle->ping_common.rtt / 8;
            if(a_ping_handle->ping_common.options & F_ADAPTIVE)
                update_interval(a_ping_handle);
        }
    }

    if(csfailed) {
        ++a_ping_handle->ping_common.nchecksum;
        --a_ping_handle->ping_common.nreceived;
    } else if(rcvd_test(a_ping_handle, seq)) {
        ++a_ping_handle->ping_common.nrepeats;
        --a_ping_handle->ping_common.nreceived;
        dupflag = 1;
    } else {
        rcvd_set(a_ping_handle, seq);
        dupflag = 0;
    }
    a_ping_handle->ping_common.confirm = a_ping_handle->ping_common.confirm_flag;

    if(a_ping_handle->ping_common.options & F_QUIET)
        return 1;

    if(a_ping_handle->ping_common.options & F_FLOOD) {
        if(!csfailed)
            write_stdout("\b \b", 3);
        else
            write_stdout("\bC", 2);
    } else {
        int i;
        uint8_t *cp, *dp;

        print_timestamp(a_ping_handle);
        log_printf("%d bytes from %s:", cc, from);

        if(pr_reply)
            pr_reply(icmph, cc);

        if(hops >= 0)
            log_printf(" ttl=%d", hops);

        if(cc < a_ping_handle->ping_common.datalen + 8) {
            log_printf(" (truncated)\n");
            return 1;
        }
        if(a_ping_handle->ping_common.timing) {
            if(triptime >= 100000)
                log_printf(" time=%ld ms", (triptime + 500) / 1000);
            else if(triptime >= 10000)
                log_printf(" time=%ld.%01ld ms", (triptime + 50) / 1000,
                        ((triptime + 50) % 1000) / 100);
            else if(triptime >= 1000)
                log_printf(" time=%ld.%02ld ms", (triptime + 5) / 1000,
                        ((triptime + 5) % 1000) / 10);
            else
                log_printf(" time=%ld.%03ld ms", triptime / 1000,
                        triptime % 1000);
            log_printf(" tsum=%d ", a_ping_handle->ping_common.tsum);
        }
        if(dupflag)
            log_printf(" (DUP!)");
        if(csfailed)
            log_printf(" (BAD CHECKSUM!)");

        /* check the data */
        cp = ((unsigned char*) ptr) + sizeof(struct timeval);
        dp = &a_ping_handle->ping_common.outpack[8 + sizeof(struct timeval)];
        for(i = sizeof(struct timeval); i < a_ping_handle->ping_common.datalen; ++i, ++cp, ++dp) {
            if(*cp != *dp) {
                log_printf("\nwrong data byte #%d should be 0x%x but was 0x%x",
                        i, *dp, *cp);
                cp = (unsigned char*) ptr + sizeof(struct timeval);
                for(i = sizeof(struct timeval); i < a_ping_handle->ping_common.datalen; ++i, ++cp) {
                    if((i % 32) == sizeof(struct timeval))
                        log_printf("\n#%d\t", i);
                    log_printf("%x ", *cp);
                }
                break;
            }
        }
    }
    return 0;
}
#ifdef PING_DBG
static long llsqrt(long long a)
{
    long long prev = LLONG_MAX;
    long long x = a;

    if (x > 0) {
        while (x < prev) {
            prev = x;
            x = (x+(a/x))/2;
        }
    }

    return (long)x;
}
#endif

/*
 * finish --
 *	Print out statistics, and give up.
 */
void finish(ping_handle_t *a_ping_handle)
{
    struct timeval tv = a_ping_handle->ping_common.cur_time;
#ifdef PING_DBG
    char *comma = "";
#endif

    tvsub(&tv, &a_ping_handle->ping_common.start_time);
#ifdef PING_DBG
    putchar('\n');
    fflush(stdout);
    printf("--- %s ping statistics ---\n", hostname);
    printf("%ld packets transmitted, ", ntransmitted);
    printf("%ld received", nreceived);
    if (nrepeats)
    log_printf(", +%ld duplicates", nrepeats);
    if (nchecksum)
    printf(", +%ld corrupted", nchecksum);
    if (nerrors)
    printf(", +%ld errors", nerrors);
    if (ntransmitted) {
#ifdef USE_IDN
        setlocale(LC_ALL, "C");
#endif
        printf(", %g%% packet loss",
                (float) ((((long long)(ntransmitted - nreceived)) * 100.0) /
                        ntransmitted));
        printf(", time %ldms", 1000*tv.tv_sec+(tv.tv_usec+500)/1000);
    }
    putchar('\n');
#endif

    if(a_ping_handle->ping_common.nreceived && a_ping_handle->ping_common.timing) {

        a_ping_handle->ping_common.tsum /= a_ping_handle->ping_common.nreceived + a_ping_handle->ping_common.nrepeats;
        a_ping_handle->ping_common.tsum2 /= a_ping_handle->ping_common.nreceived + a_ping_handle->ping_common.nrepeats;
#ifdef PING_DBG
        long tmdev;
        tmdev = llsqrt(tsum2 - tsum * tsum);
        printf("rtt min/avg/max/mdev = %ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld ms",
                (long)tmin/1000, (long)tmin%1000,
                (unsigned long)(tsum/1000), (long)(tsum%1000),
                (long)tmax/1000, (long)tmax%1000,
                (long)tmdev/1000, (long)tmdev%1000
        );
        comma = ", ";
#endif
    }
#ifdef PING_DBG
    if (pipesize > 1) {
        printf("%spipe %d", comma, pipesize);
        comma = ", ";
    }
    if (nreceived && (!interval || (a_ping_handle->ping_common.options&(F_FLOOD|F_ADAPTIVE))) && ntransmitted > 1) {
        int ipg = (1000000*(long long)tv.tv_sec+tv.tv_usec)/(ntransmitted-1);
        printf("%sipg/ewma %d.%03d/%d.%03d ms",
                comma, ipg/1000, ipg%1000, rtt/8000, (rtt/8)%1000);
    }
    putchar('\n');
    //exit(!nreceived || (deadline && nreceived < npackets));
#endif
}

void status(ping_handle_t *a_ping_handle)
{
    int loss = 0;
    long tavg = 0;

    status_snapshot = 0;

    if(a_ping_handle->ping_common.ntransmitted)
        loss = (((long long) (a_ping_handle->ping_common.ntransmitted - a_ping_handle->ping_common.nreceived)) * 100) / a_ping_handle->ping_common.ntransmitted;

    fprintf(stderr, "\r%ld/%ld packets, %d%% loss", a_ping_handle->ping_common.nreceived, a_ping_handle->ping_common.ntransmitted, loss);

    if(a_ping_handle->ping_common.nreceived && a_ping_handle->ping_common.timing) {
        tavg = a_ping_handle->ping_common.tsum / (a_ping_handle->ping_common.nreceived + a_ping_handle->ping_common.nrepeats);

        fprintf(stderr, ", min/avg/ewma/max = %ld.%03ld/%lu.%03ld/%d.%03d/%ld.%03ld ms",
                (long) a_ping_handle->ping_common.tmin / 1000, (long) a_ping_handle->ping_common.tmin % 1000,
                tavg / 1000, tavg % 1000,
                a_ping_handle->ping_common.rtt / 8000, (a_ping_handle->ping_common.rtt / 8) % 1000,
                (long) a_ping_handle->ping_common.tmax / 1000, (long) a_ping_handle->ping_common.tmax % 1000
                        );
    }
    fprintf(stderr, "\n");
}

inline int is_ours(ping_handle_t *a_ping_handle, socket_st *sock, uint16_t id) {
    return sock->socktype == SOCK_DGRAM || id == a_ping_handle->ping_common.ident;
}
