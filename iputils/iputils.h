/*
 * Set utilities for networking
 */

#ifndef _IPUTILS_H
#define _IPUTILS_H

#include <stdint.h>
#include <stdlib.h>
#ifndef _WIN32
#include <netinet/ip.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include "win32/iphdr.h"
#include "win32/ip.h"
#define uid_t uint32_t
#endif
#include <setjmp.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAXPACKET 128000    /* max packet size */

#define MAX_DUP_CHK 0x10000

#ifdef USE_BITMAP64
typedef uint64_t  bitmap_t;
# define BITMAP_SHIFT 6
#else
typedef uint32_t  bitmap_t;
# define BITMAP_SHIFT 5
#endif

struct rcvd_table {
  bitmap_t bitmap[MAX_DUP_CHK / (sizeof(bitmap_t) * 8)];
};

typedef struct ping_handle{
    int ts_type;
    int nroute;
    uint32_t route[10];

    struct sockaddr_in whereto; /* who to ping */
    int optlen;
    int settos; /* Set TOS, Precendence or other QOS options */

    int broadcast_pings;

    struct sockaddr_in source;
    char *device;
    int pmtudisc;
    struct {

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
        int interval; // interval between packets (msec)
        int preload;
        int deadline; // time to die
        int lingertime;
        struct timeval start_time, cur_time;
        //volatile int exiting;
        //volatile int status_snapshot;
        int confirm;
        volatile int in_pr_addr; // pr_addr() is executing
        jmp_buf pr_addr_jmp;

        /* Stupid workarounds for bugs/missing functionality in older linuces.
         * confirm_flag fixes refusing service of kernels without MSG_CONFIRM.
         * i.e. for linux-2.2 */
        int confirm_flag;

        // timing
        int timing; // flag to do timing
        long tmin; // minimum round trip time
        long tmax; // maximum round trip time
        /* Message for rpm maintainers: have _shame_. If you want
         * to fix something send the patch to me for sanity checking.
         * "sparcfix" patch is a complete non-sense, apparenly the person
         * prepared it was stoned.
         */
        long long tsum; // sum of all times, for doing average
        long long tsum2;
        int pipesize;

        int datalen;

        char *hostname;
        int uid;
        uid_t euid;
        int ident; // process id to identify our packets

        int screen_width;

        #ifdef HAVE_LIBCAP
        cap_value_t cap_raw;
        cap_value_t cap_admin;
        #endif
    } ping_common;
}ping_handle_t;

ping_handle_t* ping_handle_create(void);

/**
 * Send ping for ipv4
 *
 * @addr host name or IP address
 * @count number of packets to transmit
 * @return ping time in microsecond or -1 if error
 */
int ping_util(ping_handle_t *a_ping_handle, const char *addr, int count);

/**
 * Send ping for ipv6
 *
 * @addr host name or IP address
 * @count number of packets to transmit
 * @return ping time in microsecond or -1 if error
 */
int ping_util6(ping_handle_t *a_ping_handle, const char *addr, int count);


/**
 * Tracepath host
 *
 * @addr[in] host name or IP address
 * @hops[out] hops count
 * @time_usec[out] latency in microseconds
 * @return 0 Ok, -1 error
 */
int tracepath_util(const char *addr, int *hops, int *time_usec);

/**
 * Traceroute host
 *
 * @addr[in] host name or IP address
 * @hops[out] hops count
 * @time_usec[out] latency in microseconds
 * @return 0 Ok, -1 error
 */
int traceroute_util(const char *addr, int *hops, int *time_usec);


/**
 * Set verbose mode
 */
void iputils_set_verbose(void);
/**
 * Reset verbose mode
 */
void iputils_reset_verbose(void);


// analog printf()
int log_printf(const char *format, ...);

#define PACKAGE_NAME "iputils"
#define PACKAGE_VERSION "0.1"
#define IPUTILS_VERSION(_prog) "%s from %s %s\n", _prog, PACKAGE_NAME, PACKAGE_VERSION
#define UNUSED(x) (void)(x)

#ifdef __cplusplus
}
#endif

#endif // _IPUTILS_H
