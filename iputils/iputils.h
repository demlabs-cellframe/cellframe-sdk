/*
 * Set utilities for networking
 */

#ifndef _IPUTILS_H
#define _IPUTILS_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Send ping for ipv4
 *
 * @addr host name or IP address
 * @count number of packets to transmit
 * @return ping time in microsecond or -1 if error
 */
int ping_util(const char *addr, int count);

/**
 * Send ping for ipv6
 *
 * @addr host name or IP address
 * @count number of packets to transmit
 * @return ping time in microsecond or -1 if error
 */
int ping_util6(const char *addr, int count);


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
