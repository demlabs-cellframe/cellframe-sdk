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
int ping_util4(const char *addr, int count);

/**
 * Send ping for ipv6
 *
 * @addr host name or IP address
 * @count number of packets to transmit
 * @return ping time in microsecond or -1 if error
 */
int ping_util6(const char *addr, int count);


/**
 *
 */
int tracepath_util(int type, const char *addr);

//#define PING_DBG
// analog printf()
void log_printf(const char *format, ...);

#define PACKAGE_NAME "iputils"
#define PACKAGE_VERSION "0.1"
#define IPUTILS_VERSION(_prog) "%s from %s %s\n", _prog, PACKAGE_NAME, PACKAGE_VERSION

#ifdef __cplusplus
}
#endif

#endif // _IPUTILS_H
