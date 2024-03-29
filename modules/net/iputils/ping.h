
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <poll.h>

#include <sys/param.h>
#include <sys/socket.h>

#define __USE_GNU

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <linux/filter.h>
#include <linux/types.h>
#include <linux/sockios.h>

#include <sys/file.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/uio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <setjmp.h>

#include <asm/byteorder.h>
#include <sched.h>
#include <math.h>

#include <resolv.h>

#include "iputils.h"

#ifdef HAVE_ERROR_H
#include <error.h>
#else
#include <stdarg.h>
#endif

#ifdef HAVE_LIBCAP
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

#ifdef USE_IDN
#include <locale.h>
#include <idn2.h>

#ifndef AI_IDN
#define AI_IDN 0x0040
#endif
#ifndef AI_CANONIDN
#define AI_CANONIDN 0x0080
#endif
#ifndef NI_IDN
#define NI_IDN 32
#endif

#define getaddrinfo_flags (AI_CANONNAME | AI_IDN | AI_CANONIDN)
#define getnameinfo_flags NI_IDN
#else
#define getaddrinfo_flags (AI_CANONNAME)
#define getnameinfo_flags 0
#endif

#include <ifaddrs.h>
#include <netinet/in.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/errqueue.h>
#include <linux/in6.h>

#ifndef SCOPE_DELIMITER
#define SCOPE_DELIMITER '%'
#endif

#define DEFDATALEN  (64 - 8)  /* default data length */

#define MAXWAIT   10    /* max seconds to wait for response */
#define MININTERVAL 10    /* Minimal interpacket gap */
#define MINUSERINTERVAL 200   /* Minimal allowed interval for non-root */

#define SCHINT(a) (((a) <= MININTERVAL) ? MININTERVAL : (a))

/* various options */
//extern int options;
#define F_FLOOD   0x001
#define F_INTERVAL  0x002
#define F_NUMERIC 0x004
#define F_PINGFILLED  0x008
#define F_QUIET   0x010
#define F_RROUTE  0x020
#define F_SO_DEBUG  0x040
#define F_SO_DONTROUTE  0x080
#define F_VERBOSE 0x100
#define F_TIMESTAMP 0x200
#define F_SOURCEROUTE 0x400
#define F_FLOOD_POLL  0x800
#define F_LATENCY 0x1000
#define F_AUDIBLE 0x2000
#define F_ADAPTIVE  0x4000
#define F_STRICTSOURCE  0x8000
#define F_NOLOOP  0x10000
#define F_TTL   0x20000
#define F_MARK    0x40000
#define F_PTIMEOFDAY  0x80000
#define F_OUTSTANDING 0x100000
#define F_FLOWINFO  0x200000
#define F_TCLASS  0x400000

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.
 */


#if defined(__WORDSIZE) && __WORDSIZE == 64
# define USE_BITMAP64
#endif



#if ((MAX_DUP_CHK >> (BITMAP_SHIFT + 3)) << (BITMAP_SHIFT + 3)) != MAX_DUP_CHK
# error Please MAX_DUP_CHK and/or BITMAP_SHIFT
#endif



//extern struct rcvd_table rcvd_tbl;

//#define A(a_ping_handle, bit)  (a_ping_handle->ping_common.rcvd_tbl.bitmap[(bit) >> BITMAP_SHIFT])  /* identify word in array */
#define B(bit)  (((bitmap_t)1) << ((bit) & ((1 << BITMAP_SHIFT) - 1)))  /* identify bit in word */

static inline void rcvd_set(ping_handle_t *a_ping_handle, uint16_t seq)
{
  unsigned bit = seq % MAX_DUP_CHK;
  a_ping_handle->ping_common.rcvd_tbl.bitmap[(bit) >> BITMAP_SHIFT] |= B(bit);
  //A(a_ping_handle, bit) |= B(bit);
}

static inline void rcvd_clear(ping_handle_t *a_ping_handle, uint16_t seq)
{
  unsigned bit = seq % MAX_DUP_CHK;
  a_ping_handle->ping_common.rcvd_tbl.bitmap[(bit) >> BITMAP_SHIFT] &= ~B(bit);
  //A(a_ping_handle, bit) &= ~B(bit);
}

static inline bitmap_t rcvd_test(ping_handle_t *a_ping_handle, uint16_t seq)
{
  unsigned bit = seq % MAX_DUP_CHK;
  return (a_ping_handle->ping_common.rcvd_tbl.bitmap[(bit) >> BITMAP_SHIFT] & B(bit));
  //return A(a_ping_handle, bit) & B(bit);
}

#ifndef HAVE_ERROR_H
static DAP_PRINTF_ATTR(3, 4) void error(int status, int errnum, const char *format, ...)
{
  va_list ap;

  fprintf(stderr, "ping: ");
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
  if (errnum)
    fprintf(stderr, ": %s\n", strerror(errnum));
  else
    fprintf(stderr, "\n");
  if (status)
    exit(status);
}
#endif

/*
extern int datalen;
extern char *hostname;
extern int uid;
extern int ident;     // process id to identify our packets

extern int sndbuf;
extern int ttl;

extern long npackets;     // max packets to transmit
extern long nreceived;      // # of packets we got back
extern long nrepeats;     // number of duplicates
extern long ntransmitted;   // sequence # for outbound packets = #sent
extern long nchecksum;      // replies with bad checksum
extern long nerrors;      // icmp errors
extern int interval;      // interval between packets (msec)
extern int preload;
extern int deadline;      // time to die
extern int lingertime;
extern struct timeval start_time, cur_time;
extern int confirm;
extern int confirm_flag;
extern char *device;
extern int pmtudisc;

extern volatile int in_pr_addr;   // pr_addr() is executing
extern jmp_buf pr_addr_jmp;
*/

extern volatile int exiting;
extern volatile int status_snapshot;

#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif


/* timing */
/*
extern int timing;      // flag to do timing
extern long tmin;     // minimum round trip time
extern long tmax;     // maximum round trip time
extern long long tsum;      // sum of all times, for doing average
extern long long tsum2;
extern int rtt;
extern uint16_t acked;
extern int pipesize;
*/

/*
 * Write to stdout
 */
static inline void write_stdout(const char *str, size_t len)
{
  size_t o = 0;
  ssize_t cc;
  do {
    cc = write(STDOUT_FILENO, str + o, len - o);
    o += cc;
  } while (len > o || cc < 0);
}

/*
 * tvsub --
 *  Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static inline void tvsub(struct timeval *out, struct timeval *in)
{
  if ((out->tv_usec -= in->tv_usec) < 0) {
    --out->tv_sec;
    out->tv_usec += 1000000;
  }
  out->tv_sec -= in->tv_sec;
}

static inline void set_signal(int signo, void (*handler)(int))
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));

  sa.sa_handler = (void (*)(int))handler;
  sigaction(signo, &sa, NULL);
}

extern int __schedule_exit(ping_handle_t *a_ping_handle, int next);

static inline int schedule_exit(ping_handle_t  *a_ping_handle, int next)
{
  if (a_ping_handle->ping_common.npackets && a_ping_handle->ping_common.ntransmitted >= a_ping_handle->ping_common.npackets
          && !a_ping_handle->ping_common.deadline)
    next = __schedule_exit(a_ping_handle, next);
  return next;
}

static inline int in_flight(ping_handle_t *a_ping_handle)
{
  uint16_t diff = (uint16_t)a_ping_handle->ping_common.ntransmitted - a_ping_handle->ping_common.acked;
  return (diff<=0x7FFF) ? diff : a_ping_handle->ping_common.ntransmitted-a_ping_handle->ping_common.nreceived-a_ping_handle->ping_common.nerrors;
}

static inline void acknowledge(ping_handle_t *a_ping_handle, uint16_t seq)
{
  uint16_t diff = (uint16_t)a_ping_handle->ping_common.ntransmitted - seq;
  if (diff <= 0x7FFF) {
    if ((int)diff+1 > a_ping_handle->ping_common.pipesize)
        a_ping_handle->ping_common.pipesize = (int)diff+1;
    if ((int16_t)(seq - a_ping_handle->ping_common.acked) > 0 ||
        (uint16_t)a_ping_handle->ping_common.ntransmitted - a_ping_handle->ping_common.acked > 0x7FFF)
        a_ping_handle->ping_common.acked = seq;
  }
}

static inline void advance_ntransmitted(ping_handle_t  *a_ping_handle)
{
    a_ping_handle->ping_common.ntransmitted++;
  /* Invalidate acked, if 16 bit seq overflows. */
  if ((uint16_t)a_ping_handle->ping_common.ntransmitted - a_ping_handle->ping_common.acked > 0x7FFF)
      a_ping_handle->ping_common.acked = (uint16_t)a_ping_handle->ping_common.ntransmitted + 1;
}

extern void usage(void) __attribute__((noreturn));
extern void limit_capabilities(ping_handle_t *a_ping_handle);
static int enable_capability_raw(ping_handle_t *a_ping_handle);
static int disable_capability_raw(ping_handle_t *a_ping_handle);
static int enable_capability_admin(ping_handle_t *a_ping_handle);
static int disable_capability_admin(ping_handle_t *a_ping_handle);
#ifdef HAVE_LIBCAP
extern int modify_capability(cap_value_t, cap_flag_value_t);
static inline int enable_capability_raw(void)   { return modify_capability(CAP_NET_RAW,   CAP_SET);   }
static inline int disable_capability_raw(void)    { return modify_capability(CAP_NET_RAW,   CAP_CLEAR); }
static inline int enable_capability_admin(void)   { return modify_capability(CAP_NET_ADMIN, CAP_SET);   }
static inline int disable_capability_admin(void)  { return modify_capability(CAP_NET_ADMIN, CAP_CLEAR); }
#else
extern int modify_capability(ping_handle_t *a_ping_handle, int);
static inline int enable_capability_raw(ping_handle_t *a_ping_handle)     { return modify_capability(a_ping_handle, 1); }
static inline int disable_capability_raw(ping_handle_t *a_ping_handle)    { return modify_capability(a_ping_handle, 0); }
static inline int enable_capability_admin(ping_handle_t *a_ping_handle)   { return modify_capability(a_ping_handle, 1); }
static inline int disable_capability_admin(ping_handle_t *a_ping_handle)  { return modify_capability(a_ping_handle, 0); }
#endif
extern void drop_capabilities(void);

typedef struct socket_st {
  int fd;
  int socktype;
} socket_st;

char *pr_addr(ping_handle_t *a_ping_handle, void *sa, socklen_t salen);

int is_ours(ping_handle_t *a_ping_handle, socket_st *sock, uint16_t id);

int ping4_run(ping_handle_t *a_ping_handle, int argc, char **argv, struct addrinfo *ai, socket_st *sock);
int ping4_send_probe(ping_handle_t *a_ping_handle, socket_st *, void *packet, unsigned packet_size);
int ping4_receive_error_msg(ping_handle_t *a_ping_handle, socket_st *sock);
int ping4_parse_reply(ping_handle_t *a_ping_handle, socket_st *, struct msghdr *msg, int len, void *addr, struct timeval *);
void ping4_install_filter( ping_handle_t *a_ping_handle, socket_st *);

typedef struct ping_func_set_st {
  int (*send_probe)(ping_handle_t *a_ping_handle, socket_st *, void *packet, unsigned packet_size);
  int (*receive_error_msg)(ping_handle_t *a_ping_handle, socket_st *sock);
  int (*parse_reply)(ping_handle_t *a_ping_handle, socket_st *, struct msghdr *msg, int len, void *addr, struct timeval *);
  void (*install_filter)(ping_handle_t *a_ping_handle, socket_st *);
} ping_func_set_st;

extern ping_func_set_st ping4_func_set;

extern int pinger(ping_handle_t *a_ping_handle, ping_func_set_st *fset, socket_st *sock);
extern void sock_setbufs(ping_handle_t *a_ping_handle, socket_st*, int alloc);
extern void setup(ping_handle_t *a_ping_handle, socket_st *);
extern int contains_pattern_in_payload(ping_handle_t *a_ping_handle, uint8_t *ptr);
extern void main_loop(ping_handle_t *a_ping_handle, ping_func_set_st *fset, socket_st*, uint8_t *buf, int buflen);// __attribute__((noreturn));
extern void finish(ping_handle_t *a_ping_handle);// __attribute__((noreturn));
extern void status(ping_handle_t *a_ping_handle);
extern void common_options(int ch);
extern int gather_statistics(ping_handle_t *a_ping_handle, uint8_t *ptr, int icmplen,
           int cc, uint16_t seq, int hops,
           int csfailed, struct timeval *tv, char *from,
           void (*pr_reply)(uint8_t *ptr, int cc));
extern void print_timestamp(ping_handle_t *a_ping_handle);
void fill(ping_handle_t *a_ping_handle, char *patp, unsigned char *packet, unsigned packet_size);

//extern int mark;
//extern unsigned char outpack[MAXPACKET];

/* IPv6 */

int ping6_run(ping_handle_t *a_ping_handle, int argc, char **argv, struct addrinfo *ai, socket_st *sock);
void ping6_usage(unsigned from_ping);

int ping6_send_probe(ping_handle_t *a_ping_handle, socket_st *sockets, void *packet, unsigned packet_size);
int ping6_receive_error_msg(ping_handle_t *a_ping_handle, socket_st *sock);
int ping6_parse_reply(ping_handle_t *a_ping_handle, socket_st *, struct msghdr *msg, int len, void *addr, struct timeval *);
void ping6_install_filter(ping_handle_t *a_ping_handle, socket_st *sockets);

extern ping_func_set_st ping6_func_set;

int niquery_option_handler(const char *opt_arg);

extern uint32_t tclass;
extern uint32_t flowlabel;
extern struct sockaddr_in6 source6;
extern struct sockaddr_in6 whereto6;
extern struct sockaddr_in6 firsthop6;

/* IPv6 node information query */

#define NI_NONCE_SIZE     8

struct ni_hdr {
  struct icmp6_hdr    ni_u;
  uint8_t       ni_nonce[NI_NONCE_SIZE];
};

#define ni_type   ni_u.icmp6_type
#define ni_code   ni_u.icmp6_code
#define ni_cksum  ni_u.icmp6_cksum
#define ni_qtype  ni_u.icmp6_data16[0]
#define ni_flags  ni_u.icmp6_data16[1]

/* Types */
#ifndef ICMPV6_NI_QUERY
# define ICMPV6_NI_QUERY    139
# define ICMPV6_NI_REPLY    140
#endif

/* Query Codes */
#define NI_SUBJ_IPV6      0
#define NI_SUBJ_NAME      1
#define NI_SUBJ_IPV4      2

/* Reply Codes */
#define NI_SUCCESS      0
#define NI_REFUSED      1
#define NI_UNKNOWN      2

/* Qtypes */
#define NI_QTYPE_NOOP     0
#define NI_QTYPE_NAME     2
#define NI_QTYPE_IPV6ADDR   3
#define NI_QTYPE_IPV4ADDR   4

/* Flags */
#define NI_IPV6ADDR_F_TRUNCATE    __constant_cpu_to_be16(0x0001)
#define NI_IPV6ADDR_F_ALL   __constant_cpu_to_be16(0x0002)
#define NI_IPV6ADDR_F_COMPAT    __constant_cpu_to_be16(0x0004)
#define NI_IPV6ADDR_F_LINKLOCAL   __constant_cpu_to_be16(0x0008)
#define NI_IPV6ADDR_F_SITELOCAL   __constant_cpu_to_be16(0x0010)
#define NI_IPV6ADDR_F_GLOBAL    __constant_cpu_to_be16(0x0020)

#define NI_IPV4ADDR_F_TRUNCATE    NI_IPV6ADDR_F_TRUNCATE
#define NI_IPV4ADDR_F_ALL   NI_IPV6ADDR_F_ALL


