/*
 *
 *  Modified for AF_INET6 by Pedro Roque
 *
 *  <roque@di.fc.ul.pt>
 *
 *  Original copyright notice included bellow
 */

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
 *      P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *  Mike Muuss
 *  U. S. Army Ballistic Research Laboratory
 *  December, 1983
 *
 * Status -
 *  Public Domain.  Distribution Unlimited.
 * Bugs -
 *  More statistics could always be gathered.
 *  If kernel does not support non-raw ICMP sockets or
 *  if -N option is used, this program has to run SUID to ROOT or
 *  with net_cap_raw enabled.
 */

#include "ping.h"

/* IPv6 packet information.  */
//struct in6_pktinfo
//  {
//    struct in6_addr ipi6_addr;  /* src/dst IPv6 address */
//    unsigned int ipi6_ifindex;  /* send/recv interface index */
//  };

ping_func_set_st ping6_func_set = {
    .send_probe = ping6_send_probe,
    .receive_error_msg = ping6_receive_error_msg,
    .parse_reply = ping6_parse_reply,
    .install_filter = ping6_install_filter
};

#ifndef SCOPE_DELIMITER
# define SCOPE_DELIMITER '%'
#endif

uint32_t flowlabel;
uint32_t tclass;

static struct sockaddr_in6 whereto;
static struct sockaddr_in6 firsthop;

static unsigned char cmsgbuf[4096];
static size_t cmsglen = 0;

static int pr_icmph(uint8_t type, uint8_t code, uint32_t info);

struct sockaddr_in6 source6 = { .sin6_family = AF_INET6 };
//extern char *device;

#if defined(USE_GCRYPT) || defined(USE_OPENSSL) || defined(USE_NETTLE)
#include "iputils_md5dig.h"
#define USE_CRYPTO
#endif

/* Node Information query */
int ni_query = -1;
int ni_flag = 0;
void *ni_subject = NULL;
int ni_subject_len = 0;
int ni_subject_type = -1;
char *ni_group;

static inline int ntohsp(uint16_t *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return ntohs(v);
}

unsigned int if_name2index(const char *ifname)
{
    unsigned int i = if_nametoindex(ifname);
    if(!i)
        error(2, 0, "unknown iface: %s", ifname);
    return i;
}

struct niquery_option {
    char *name;
    int namelen;
    int has_arg;
    int data;
    int (*handler)(int index, const char *arg);
};

#define NIQUERY_OPTION(_name, _has_arg, _data, _handler)  \
  {             \
    .name = _name,          \
    .namelen = sizeof(_name) - 1,     \
    .has_arg = _has_arg,        \
    .data = _data,          \
    .handler = _handler       \
  }

static int niquery_option_name_handler(int index __attribute__((__unused__)),
        const char *arg __attribute__((__unused__)));
static int niquery_option_ipv6_handler(int index __attribute__((__unused__)),
        const char *arg __attribute__((__unused__)));
static int niquery_option_ipv6_flag_handler(int index, const char *arg);
static int niquery_option_ipv4_handler(int index, const char *arg);
static int niquery_option_ipv4_flag_handler(int index, const char *arg);
static int niquery_option_subject_addr_handler(int index, const char *arg);
static int niquery_option_subject_name_handler(int index, const char *arg);
static int niquery_option_help_handler(int index, const char *arg);

struct niquery_option niquery_options[] = {
NIQUERY_OPTION("name", 0, 0, niquery_option_name_handler),
NIQUERY_OPTION("fqdn", 0, 0, niquery_option_name_handler),
NIQUERY_OPTION("ipv6", 0, 0, niquery_option_ipv6_handler),
NIQUERY_OPTION("ipv6-all", 0, NI_IPV6ADDR_F_ALL, niquery_option_ipv6_flag_handler),
NIQUERY_OPTION("ipv6-compatible", 0, NI_IPV6ADDR_F_COMPAT, niquery_option_ipv6_flag_handler),
NIQUERY_OPTION("ipv6-linklocal", 0, NI_IPV6ADDR_F_LINKLOCAL, niquery_option_ipv6_flag_handler),
NIQUERY_OPTION("ipv6-sitelocal", 0, NI_IPV6ADDR_F_SITELOCAL, niquery_option_ipv6_flag_handler),
NIQUERY_OPTION("ipv6-global", 0, NI_IPV6ADDR_F_GLOBAL, niquery_option_ipv6_flag_handler),
NIQUERY_OPTION("ipv4", 0, 0, niquery_option_ipv4_handler),
NIQUERY_OPTION("ipv4-all", 0, NI_IPV4ADDR_F_ALL, niquery_option_ipv4_flag_handler),
NIQUERY_OPTION("subject-ipv6", 1, NI_SUBJ_IPV6, niquery_option_subject_addr_handler),
NIQUERY_OPTION("subject-ipv4", 1, NI_SUBJ_IPV4, niquery_option_subject_addr_handler),
NIQUERY_OPTION("subject-name", 1, 0, niquery_option_subject_name_handler),
NIQUERY_OPTION("subject-fqdn", 1, -1, niquery_option_subject_name_handler),
NIQUERY_OPTION("help", 0, 0, niquery_option_help_handler),
    { NULL, 0, 0, 0, NULL }
};

static inline int niquery_is_enabled(void)
{
    return ni_query >= 0;
}

#if PING6_NONCE_MEMORY
uint8_t *ni_nonce_ptr;
#else
struct {
    struct timeval tv;
    pid_t pid;
} ni_nonce_secret;
#endif

static void niquery_init_nonce(void)
{
#if PING6_NONCE_MEMORY
    struct timeval tv;
    unsigned long seed;

    seed = (unsigned long)getpid();
    if (!gettimeofday(&tv, NULL))
    seed ^= tv.tv_usec;
    srand(seed);

    ni_nonce_ptr = calloc(NI_NONCE_SIZE, MAX_DUP_CHK);
    if (!ni_nonce_ptr)
    error(2, errno, "calloc");

    ni_nonce_ptr[0] = ~0;
#else
    gettimeofday(&ni_nonce_secret.tv, NULL);
    ni_nonce_secret.pid = getpid();
#endif
}

#if !PING6_NONCE_MEMORY
static int niquery_nonce(uint8_t *nonce, int fill)
{
# ifdef USE_CRYPTO
    static uint8_t digest[MD5_DIGEST_LENGTH];
    static int seq = -1;

    if (fill || seq != *(uint16_t *)nonce || seq < 0) {
        MD5_CTX ctxt;

        MD5_Init(&ctxt);
        MD5_Update(&ctxt, &ni_nonce_secret, sizeof(ni_nonce_secret));
        MD5_Update(&ctxt, nonce, sizeof(uint16_t));
        MD5_Final(digest, &ctxt);

        seq = *(uint16_t *)nonce;
    }

    if (fill) {
        memcpy(nonce + sizeof(uint16_t), digest, NI_NONCE_SIZE - sizeof(uint16_t));
        return 0;
    } else {
        if (memcmp(nonce + sizeof(uint16_t), digest, NI_NONCE_SIZE - sizeof(uint16_t)))
        return -1;
        return ntohsp((uint16_t *)nonce);
    }
# else
    error(3, ENOSYS, "niquery_nonce() crypto disabled");
# endif
    if(nonce || fill)
        return -1;
    return -1;
}
#endif

static inline void niquery_fill_nonce(uint16_t seq, uint8_t *nonce)
{
    uint16_t v = htons(seq);
#if PING6_NONCE_MEMORY
    int i;

    memcpy(&ni_nonce_ptr[NI_NONCE_SIZE * (seq % MAX_DUP_CHK)], &v, sizeof(v));

    for (i = sizeof(v); i < NI_NONCE_SIZE; i++)
    ni_nonce_ptr[NI_NONCE_SIZE * (seq % MAX_DUP_CHK) + i] = 0x100 * (rand() / (RAND_MAX + 1.0));

    memcpy(nonce, &ni_nonce_ptr[NI_NONCE_SIZE * (seq % MAX_DUP_CHK)], NI_NONCE_SIZE);
#else
    memcpy(nonce, &v, sizeof(v));
    niquery_nonce(nonce, 1);
#endif
}

static inline int niquery_check_nonce(uint8_t *nonce)
{
#if PING6_NONCE_MEMORY
    uint16_t seq = ntohsp((uint16_t *)nonce);
    if (memcmp(nonce, &ni_nonce_ptr[NI_NONCE_SIZE * (seq % MAX_DUP_CHK)], NI_NONCE_SIZE))
    return -1;
    return seq;
#else
    return niquery_nonce(nonce, 0);
#endif
}

static int niquery_set_qtype(int type)
{
    if(niquery_is_enabled() && ni_query != type) {
        printf("Qtype conflict\n");
        return -1;
    }
    ni_query = type;
    return 0;
}

static int niquery_option_name_handler(int index __attribute__((__unused__)),
        const char *arg __attribute__((__unused__)))
{
    if(niquery_set_qtype(NI_QTYPE_NAME) < 0)
        return -1;
    return 0;
}

static int niquery_option_ipv6_handler(int index __attribute__((__unused__)),
        const char *arg __attribute__((__unused__)))
{
    if(niquery_set_qtype(NI_QTYPE_IPV6ADDR) < 0)
        return -1;
    return 0;
}

static int niquery_option_ipv6_flag_handler(int index, const char *arg __attribute__((__unused__)))
{
    if(niquery_set_qtype(NI_QTYPE_IPV6ADDR) < 0)
        return -1;
    ni_flag |= niquery_options[index].data;
    return 0;
}

static int niquery_option_ipv4_handler(int index __attribute__((__unused__)),
        const char *arg __attribute__((__unused__)))
{
    if(niquery_set_qtype(NI_QTYPE_IPV4ADDR) < 0)
        return -1;
    return 0;
}

static int niquery_option_ipv4_flag_handler(int index, const char *arg __attribute__((__unused__)))
{
    if(niquery_set_qtype(NI_QTYPE_IPV4ADDR) < 0)
        return -1;
    ni_flag |= niquery_options[index].data;
    return 0;
}

static inline int niquery_is_subject_valid(void)
{
    return ni_subject_type >= 0 && ni_subject;
}

static int niquery_set_subject_type(int type)
{
    if(niquery_is_subject_valid() && ni_subject_type != type) {
        printf("Subject type conflict\n");
        return -1;
    }
    ni_subject_type = type;
    return 0;
}

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define OFFSET_OF(type,elem)  ((size_t)&((type *)0)->elem)

static int niquery_option_subject_addr_handler(int index, const char *arg)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_flags = getaddrinfo_flags };
    struct addrinfo *result, *ai;
    int status;
    int offset;

    if(niquery_set_subject_type(niquery_options[index].data) < 0)
        return -1;

    ni_subject_type = niquery_options[index].data;

    switch (niquery_options[index].data) {
    case NI_SUBJ_IPV6:
        ni_subject_len = sizeof(struct in6_addr);
        offset = OFFSET_OF(struct sockaddr_in6, sin6_addr);
        hints.ai_family = AF_INET6;
        break;
    case NI_SUBJ_IPV4:
        ni_subject_len = sizeof(struct in_addr);
        offset = OFFSET_OF(struct sockaddr_in, sin_addr);
        hints.ai_family = AF_INET;
        break;
    default:
        /* should not happen. */
        offset = -1;
    }

    status = getaddrinfo(arg, 0, &hints, &result);
    if(status) {
        error(0, 0, "%s: %s", arg, gai_strerror(status));
        return -1;
    }

    for(ai = result; ai; ai = ai->ai_next) {
        void *p = malloc(ni_subject_len);
        if(!p)
            continue;
        memcpy(p, (uint8_t *) ai->ai_addr + offset, ni_subject_len);
        free(ni_subject);
        ni_subject = p;
        break;
    }
    freeaddrinfo(result);

    return 0;
}

#ifdef USE_IDN
# if IDN2_VERSION_NUMBER >= 0x02000000
#  define IDN2_FLAGS IDN2_NONTRANSITIONAL
# else
#  define IDN2_FLAGS 0
# endif
#endif

#ifdef USE_CRYPTO
static int niquery_option_subject_name_handler(int index, const char *name)
{
    static char nigroup_buf[INET6_ADDRSTRLEN + 1 + IFNAMSIZ];
    unsigned char *dnptrs[2], **dpp, **lastdnptr;
    int n;
    size_t i;
    char *p;
    char *canonname = NULL, *idn = NULL;
    unsigned char *buf = NULL;
    size_t namelen;
    size_t buflen;
    int dots, fqdn = niquery_options[index].data;
    MD5_CTX ctxt;
    uint8_t digest[MD5_DIGEST_LENGTH];
#ifdef USE_IDN
    int rc;
#endif

    if (niquery_set_subject_type(NI_SUBJ_NAME) < 0)
    return -1;

#ifdef USE_IDN
    rc = idn2_lookup_ul(name, &idn, IDN2_FLAGS);
    if (rc)
    error(2, 0, "IDN encoding error: %s", idn2_strerror(rc));
#else
    idn = strdup(name);
    if (!idn)
    goto oomexit;
#endif

    p = strchr(idn, SCOPE_DELIMITER);
    if (p) {
        *p = '\0';
        if (strlen(p + 1) >= IFNAMSIZ)
        error(1, 0, "too long scope name");
    }

    namelen = strlen(idn);
    canonname = malloc(namelen + 1);
    if (!canonname)
    goto oomexit;

    dots = 0;
    for (i = 0; i < namelen + 1; i++) {
        canonname[i] = isupper(idn[i]) ? tolower(idn[i]) : idn[i];
        if (idn[i] == '.')
        dots++;
    }

    if (fqdn == 0) {
        /* guess if hostname is FQDN */
        fqdn = dots ? 1 : -1;
    }

    buflen = namelen + 3 + 1; /* dn_comp() requrires strlen() + 3,
     plus non-fqdn indicator. */
    buf = malloc(buflen);
    if (!buf) {
        error(0, errno, "memory allocation failed");
        goto errexit;
    }

    dpp = dnptrs;
    lastdnptr = &dnptrs[ARRAY_SIZE(dnptrs)];

    *dpp++ = (unsigned char *)buf;
    *dpp++ = NULL;

    n = dn_comp(canonname, (unsigned char *)buf, buflen, dnptrs, lastdnptr);
    if (n < 0) {
        error(0, 0, "inappropriate subject name: %s", canonname);
        goto errexit;
    } else if ((size_t) n >= buflen) {
        error(0, 0, "dn_comp() returned too long result");
        goto errexit;
    }

    MD5_Init(&ctxt);
    MD5_Update(&ctxt, buf, buf[0]);
    MD5_Final(digest, &ctxt);

    sprintf(nigroup_buf, "ff02::2:%02x%02x:%02x%02x%s%s",
            digest[0], digest[1], digest[2], digest[3],
            p ? "%" : "",
            p ? p + 1 : "");

    if (fqdn < 0)
    buf[n] = 0;

    free(ni_subject);

    ni_group = nigroup_buf;
    ni_subject = buf;
    ni_subject_len = n + (fqdn < 0);
    ni_group = nigroup_buf;

    free(canonname);
    free(idn);

    return 0;
    oomexit:
    error(0, errno, "memory allocation failed");
    errexit:
    free(buf);
    free(canonname);
    free(idn);
    exit(1);
}
#else
static int niquery_option_subject_name_handler(int index __attribute__((__unused__)),
        const char *name __attribute__((__unused__)))
{
    error(3, ENOSYS, "niquery_option_subject_name_handler() crypto disabled");
    return -1;
}
#endif

int niquery_option_help_handler(int index __attribute__((__unused__)), const char *arg __attribute__((__unused__)))
{
    fprintf(stderr, "ping -6 -N <nodeinfo opt>\n"
            "Help:\n"
            "  help\n"
            "Query:\n"
            "  name\n"
            "  ipv6\n"
            "  ipv6-all\n"
            "  ipv6-compatible\n"
            "  ipv6-global\n"
            "  ipv6-linklocal\n"
            "  ipv6-sitelocal\n"
            "  ipv4\n"
            "  ipv4-all\n"
            "Subject:\n"
            "  subject-ipv6=addr\n"
            "  subject-ipv4=addr\n"
            "  subject-name=name\n"
            "  subject-fqdn=name\n"
            );
    exit(2);
}

int niquery_option_handler(const char *opt_arg)
{
    struct niquery_option *p;
    int i;
    int ret = -1;
    for(i = 0, p = niquery_options; p->name; i++, p++) {
        if(strncmp(p->name, opt_arg, p->namelen))
            continue;
        if(!p->has_arg) {
            if(opt_arg[p->namelen] == '\0') {
                ret = p->handler(i, NULL);
                if(ret >= 0)
                    break;
            }
        } else {
            if(opt_arg[p->namelen] == '=') {
                ret = p->handler(i, &opt_arg[p->namelen] + 1);
                if(ret >= 0)
                    break;
            }
        }
    }
    if(!p->name)
        ret = niquery_option_help_handler(0, NULL);
    return ret;
}

int ping6_run(ping_handle_t *a_ping_handle, int argc, char **argv, struct addrinfo *ai, struct socket_st *sock)
{
    static const struct addrinfo hints = { .ai_family = AF_INET6, .ai_flags = getaddrinfo_flags };
    struct addrinfo *result = NULL;
    int status;
    int hold, packlen;
    unsigned char *packet;
    char *target;
    struct icmp6_filter filter;
    int err;
    static uint32_t scope_id = 0;

    if(niquery_is_enabled()) {
        niquery_init_nonce();

        if(!niquery_is_subject_valid()) {
            ni_subject = &whereto.sin6_addr;
            ni_subject_len = sizeof(whereto.sin6_addr);
            ni_subject_type = NI_SUBJ_IPV6;
        }
    }

    if(argc > 1) {
        usage();
    } else if(argc == 1) {
        target = *argv;
    } else {
        if(ni_query < 0 && ni_subject_type != NI_SUBJ_NAME)
            usage();
        target = ni_group;
    }

    if(!ai) {
        status = getaddrinfo(target, NULL, &hints, &result);
        if(status)
            error(2, 0, "%s: %s", target, gai_strerror(status));
        ai = result;
    }

    memcpy(&whereto, ai->ai_addr, sizeof(whereto));
    whereto.sin6_port = htons(IPPROTO_ICMPV6);

    if(result)
        freeaddrinfo(result);

    if(memchr(target, ':', strlen(target)))
        a_ping_handle->ping_common.options |= F_NUMERIC;

    if(IN6_IS_ADDR_UNSPECIFIED(&firsthop.sin6_addr)) {
        memcpy(&firsthop.sin6_addr, &whereto.sin6_addr, 16);
        firsthop.sin6_scope_id = whereto.sin6_scope_id;
        /* Verify scope_id is the same as intermediate nodes */
        if(firsthop.sin6_scope_id && scope_id && firsthop.sin6_scope_id != scope_id)
            error(2, 0, "scope discrepancy among the nodes");
        else if(!scope_id)
            scope_id = firsthop.sin6_scope_id;
    }

    a_ping_handle->ping_common.hostname = target;

    if(IN6_IS_ADDR_UNSPECIFIED(&source6.sin6_addr)) {
        socklen_t alen;
        int probe_fd = socket(AF_INET6, SOCK_DGRAM, 0);

        if(probe_fd < 0)
            error(2, errno, "socket");
        if(a_ping_handle->device) {
            unsigned int iface = if_name2index(a_ping_handle->device);
#ifdef IPV6_RECVPKTINFO
            struct in6_pktinfo ipi;

            memset(&ipi, 0, sizeof(ipi));
            ipi.ipi6_ifindex = iface;
#endif

            if(IN6_IS_ADDR_LINKLOCAL(&firsthop.sin6_addr) ||
                    IN6_IS_ADDR_MC_LINKLOCAL(&firsthop.sin6_addr))
                firsthop.sin6_scope_id = iface;
            enable_capability_raw(a_ping_handle);
#ifdef IPV6_RECVPKTINFO
            if(
            setsockopt(probe_fd, IPPROTO_IPV6, IPV6_PKTINFO, &ipi, sizeof ipi) == -1 ||
                    setsockopt(sock->fd, IPPROTO_IPV6, IPV6_PKTINFO, &ipi, sizeof ipi) == -1) {
                perror("setsockopt(IPV6_PKTINFO)");
                exit(2);
            }
#endif
            if(
            setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, a_ping_handle->device, strlen(a_ping_handle->device) + 1) == -1 ||
                    setsockopt(sock->fd, SOL_SOCKET, SO_BINDTODEVICE, a_ping_handle->device, strlen(a_ping_handle->device) + 1) == -1) {
                error(2, errno, "setsockopt(SO_BINDTODEVICE) %s", a_ping_handle->device);
            }
            disable_capability_raw(a_ping_handle);
        }

        if(!IN6_IS_ADDR_LINKLOCAL(&firsthop.sin6_addr) &&
                !IN6_IS_ADDR_MC_LINKLOCAL(&firsthop.sin6_addr))
            firsthop.sin6_family = AF_INET6;

        firsthop.sin6_port = htons(1025);
        if(connect(probe_fd, (struct sockaddr*) &firsthop, sizeof(firsthop)) == -1)
            error(2, errno, "connect");
        alen = sizeof source6;
        if(getsockname(probe_fd, (struct sockaddr *) &source6, &alen) == -1)
            error(2, errno, "getsockname");
        source6.sin6_port = 0;
        close(probe_fd);

        if(a_ping_handle->device) {
            struct ifaddrs *ifa0, *ifa;

            if(getifaddrs(&ifa0))
                error(2, errno, "getifaddrs");

            for(ifa = ifa0; ifa; ifa = ifa->ifa_next) {
                if(!ifa->ifa_name || !ifa->ifa_addr ||
                        ifa->ifa_addr->sa_family != AF_INET6)
                    continue;
                if(!strcmp(ifa->ifa_name, a_ping_handle->device) &&
                        IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 * )ifa->ifa_addr)->sin6_addr,
                                &source6.sin6_addr))
                    break;
            }
            if(!ifa)
                error(0, 0, "Warning: source address might be selected on device other than: %s", a_ping_handle->device);

            freeifaddrs(ifa0);
        }
    }
    else if(a_ping_handle->device && (IN6_IS_ADDR_LINKLOCAL(&source6.sin6_addr) ||
            IN6_IS_ADDR_MC_LINKLOCAL(&source6.sin6_addr)))
        source6.sin6_scope_id = if_name2index(a_ping_handle->device);

    if(a_ping_handle->device) {
        struct cmsghdr *cmsg;
        struct in6_pktinfo *ipi;

        cmsg = (struct cmsghdr*) (cmsgbuf + cmsglen);
        cmsglen += CMSG_SPACE(sizeof(*ipi));
        cmsg->cmsg_len = CMSG_LEN(sizeof(*ipi));
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;

        ipi = (struct in6_pktinfo*) CMSG_DATA(cmsg);
        memset(ipi, 0, sizeof(*ipi));
        ipi->ipi6_ifindex = if_name2index(a_ping_handle->device);
    }

    if((whereto.sin6_addr.s6_addr16[0] & htons(0xff00)) == htons(0xff00)) {
        if(a_ping_handle->ping_common.uid) {
            if(a_ping_handle->ping_common.interval < 1000)
                error(2, 0, "multicast ping with too short interval: %d", a_ping_handle->ping_common.interval);
            if(a_ping_handle->pmtudisc >= 0 && a_ping_handle->pmtudisc != IPV6_PMTUDISC_DO)
                error(2, 0, "multicast ping does not fragment");
        }
        if(a_ping_handle->pmtudisc < 0)
            a_ping_handle->pmtudisc = IPV6_PMTUDISC_DO;
    }

    if(a_ping_handle->pmtudisc >= 0) {
        if(setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &a_ping_handle->pmtudisc, sizeof (a_ping_handle->pmtudisc)) == -1)
            error(2, errno, "IPV6_MTU_DISCOVER");
    }

    if((a_ping_handle->ping_common.options & F_STRICTSOURCE) &&
            bind(sock->fd, (struct sockaddr *) &source6, sizeof source6) == -1)
        error(2, errno, "bind icmp socket");

    if((ssize_t) a_ping_handle->ping_common.datalen >= (ssize_t) sizeof(struct timeval) && (ni_query < 0)) {
        /* can we time transfer */
        a_ping_handle->ping_common.timing = 1;
    }
    packlen = a_ping_handle->ping_common.datalen + 8 + 4096 + 40 + 8; /* 4096 for rthdr */
    if(!(packet = (unsigned char *) malloc((unsigned int) packlen)))
        error(2, errno, "memory allocation failed");

    hold = 1;

    /* Estimate memory eaten by single packet. It is rough estimate.
     * Actually, for small datalen's it depends on kernel side a lot. */
    hold = a_ping_handle->ping_common.datalen + 8;
    hold += ((hold + 511) / 512) * (40 + 16 + 64 + 160);
    sock_setbufs(a_ping_handle,sock, hold);

#ifdef __linux__
    if(sock->socktype == SOCK_RAW) {
        int csum_offset = 2;
        int sz_opt = sizeof(int);

        err = setsockopt(sock->fd, SOL_RAW, IPV6_CHECKSUM, &csum_offset, sz_opt);
        if(err < 0) {
            /* checksum should be enabled by default and setting this
             * option might fail anyway.
             */
            error(0, errno, "setsockopt(RAW_CHECKSUM) failed - try to continue");
        }
#else
        {
#endif

        /*
         *  select icmp echo reply as icmp type to receive
         */

        ICMP6_FILTER_SETBLOCKALL(&filter);

        ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filter);
        ICMP6_FILTER_SETPASS(ICMP6_PACKET_TOO_BIG, &filter);
        ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &filter);
        ICMP6_FILTER_SETPASS(ICMP6_PARAM_PROB, &filter);

        if(niquery_is_enabled())
            ICMP6_FILTER_SETPASS(ICMPV6_NI_REPLY, &filter);
        else
            ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);

        err = setsockopt(sock->fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof filter);

        if(err < 0)
            error(2, errno, "setsockopt(ICMP6_FILTER)");
    }

    if(a_ping_handle->ping_common.options & F_NOLOOP) {
        int loop = 0;
        if(setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof loop) == -1)
            error(2, errno, "can't disable multicast loopback");
    }
    if(a_ping_handle->ping_common.options & F_TTL) {
        if(setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &a_ping_handle->ping_common.ttl, sizeof (a_ping_handle->ping_common.ttl)) == -1)
            error(2, errno, "can't set multicast hop limit");
        if(setsockopt(sock->fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &a_ping_handle->ping_common.ttl, sizeof (a_ping_handle->ping_common.ttl)) == -1)
            error(2, errno, "can't set unicast hop limit");
    }

    const int on = 1;
    if(
    #ifdef IPV6_RECVHOPLIMIT
    setsockopt(sock->fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof on) == -1 &&
            setsockopt(sock->fd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &on, sizeof on) == -1
                    #else
                    setsockopt(sock->fd, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof on) == -1
#endif
                    )
        error(2, errno, "can't receive hop limit");

    if(a_ping_handle->ping_common.options & F_TCLASS) {
#ifdef IPV6_TCLASS
        if(setsockopt(sock->fd, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof tclass) == -1)
            error(2, errno, "setsockopt(IPV6_TCLASS)");
#else
        error(0, 0, "traffic class is not supported");
#endif
    }

    if(a_ping_handle->ping_common.options & F_FLOWINFO) {
#ifdef IPV6_FLOWLABEL_MGR
        char freq_buf[CMSG_ALIGN(sizeof(struct in6_flowlabel_req)) + cmsglen];
        struct in6_flowlabel_req *freq = (struct in6_flowlabel_req *)freq_buf;
        int freq_len = sizeof(*freq);
        memset(freq, 0, sizeof(*freq));
        freq->flr_label = htonl(flowlabel & IPV6_FLOWINFO_FLOWLABEL);
        freq->flr_action = IPV6_FL_A_GET;
        freq->flr_flags = IPV6_FL_F_CREATE;
        freq->flr_share = IPV6_FL_S_EXCL;
        memcpy(&freq->flr_dst, &whereto.sin6_addr, 16);
        if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, freq, freq_len) == -1)
        error(2, errno, "can't set flowlabel");
        flowlabel = freq->flr_label;
#else
        error(2, 0, "flow labels are not supported");
#endif

#ifdef IPV6_FLOWINFO_SEND
        whereto.sin6_flowinfo = flowlabel;
        if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof on) == -1)
        error(2, errno, "can't send flowinfo");
#else
        error(2, 0, "flowinfo is not supported");
#endif
    }

    printf("PING %s(%s) ", a_ping_handle->ping_common.hostname, pr_addr(a_ping_handle, &whereto, sizeof whereto));
    if(flowlabel)
        printf(", flow 0x%05x, ", (unsigned) ntohl(flowlabel));
    if(a_ping_handle->device || (a_ping_handle->ping_common.options & F_STRICTSOURCE)) {
        int saved_options = a_ping_handle->ping_common.options;

        a_ping_handle->ping_common.options |= F_NUMERIC;
        printf("from %s %s: ", pr_addr(a_ping_handle, &source6, sizeof source6), a_ping_handle->device ? a_ping_handle->device : "");
        a_ping_handle->ping_common.options = saved_options;
    }
    printf("%d data bytes\n", a_ping_handle->ping_common.datalen);

    setup(a_ping_handle, sock);

    drop_capabilities();

    main_loop(a_ping_handle, &ping6_func_set, sock, packet, packlen);
    return 0;
}

int ping6_receive_error_msg(ping_handle_t *a_ping_handle, socket_st *sock)
{
    ssize_t res;
    char cbuf[512];
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct sock_extended_err *e;
    struct icmp6_hdr icmph;
    struct sockaddr_in6 target;
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

    res = recvmsg(sock->fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
    if(res < 0)
        goto out;

    e = NULL;
    for(cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if(cmsg->cmsg_level == IPPROTO_IPV6) {
            if(cmsg->cmsg_type == IPV6_RECVERR)
                e = (struct sock_extended_err *) CMSG_DATA(cmsg);
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
            error(0, e->ee_errno, "local error");
        else
            error(0, 0, "local error: message too long, mtu: %u", e->ee_info);
        a_ping_handle->ping_common.nerrors++;
    } else if(e->ee_origin == SO_EE_ORIGIN_ICMP6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*) (e + 1);

        if((size_t) res < sizeof(icmph) ||
                memcmp(&target.sin6_addr, &whereto.sin6_addr, 16) ||
                icmph.icmp6_type != ICMP6_ECHO_REQUEST ||
                !is_ours(a_ping_handle, sock, icmph.icmp6_id)) {
            /* Not our error, not an error at all. Clear. */
            saved_errno = 0;
            goto out;
        }

        net_errors++;
        a_ping_handle->ping_common.nerrors++;
        if(a_ping_handle->ping_common.options & F_QUIET)
            goto out;
        if(a_ping_handle->ping_common.options & F_FLOOD) {
            write_stdout("\bE", 2);
        } else {
            print_timestamp(a_ping_handle);
            printf("From %s icmp_seq=%u ", pr_addr(a_ping_handle, sin6, sizeof *sin6), ntohs(icmph.icmp6_seq));
            pr_icmph(e->ee_type, e->ee_code, e->ee_info);
            putchar('\n');
            fflush(stdout);
        }
    }

    out:
    errno = saved_errno;
    return net_errors ? net_errors : -local_errors;
}

/*
 * pinger --
 *  Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
static int build_echo(ping_handle_t *a_ping_handle, uint8_t *_icmph, unsigned packet_size __attribute__((__unused__)))
{
    struct icmp6_hdr *icmph;
    int cc;

    icmph = (struct icmp6_hdr *) _icmph;
    icmph->icmp6_type = ICMP6_ECHO_REQUEST;
    icmph->icmp6_code = 0;
    icmph->icmp6_cksum = 0;
    icmph->icmp6_seq= htons(a_ping_handle->ping_common.ntransmitted+1);
    icmph->icmp6_id= a_ping_handle->ping_common.ident;

    if(a_ping_handle->ping_common.timing)
        gettimeofday((struct timeval *) &_icmph[8],
                (struct timezone *) NULL);

    cc = a_ping_handle->ping_common.datalen + 8; /* skips ICMP portion */

    return cc;
}

static int build_niquery(ping_handle_t *a_ping_handle, uint8_t *_nih, unsigned packet_size __attribute__((__unused__)))
{
    struct ni_hdr *nih;
    int cc;

    nih = (struct ni_hdr *) _nih;
    nih->ni_cksum = 0;

    nih->ni_type = ICMPV6_NI_QUERY;
    cc = sizeof(*nih);
    a_ping_handle->ping_common.datalen = 0;

    niquery_fill_nonce(a_ping_handle->ping_common.ntransmitted + 1, nih->ni_nonce);
    nih->ni_code = ni_subject_type;
    nih->ni_qtype= htons(ni_query);
    nih->ni_flags= ni_flag;
    memcpy(nih + 1, ni_subject, ni_subject_len);
    cc += ni_subject_len;

    return cc;
}

int ping6_send_probe(ping_handle_t *a_ping_handle, socket_st *sock, void *packet, unsigned packet_size)
{
    int len, cc;

    rcvd_clear(a_ping_handle, a_ping_handle->ping_common.ntransmitted + 1);

    if(niquery_is_enabled())
        len = build_niquery(a_ping_handle, packet, packet_size);
    else
        len = build_echo(a_ping_handle, packet, packet_size);

    if(cmsglen == 0) {
        cc = sendto(sock->fd, (char *) packet, len, a_ping_handle->ping_common.confirm,
                (struct sockaddr *) &whereto,
                sizeof(struct sockaddr_in6));
    } else {
        struct msghdr mhdr;
        struct iovec iov;

        iov.iov_len = len;
        iov.iov_base = packet;

        memset(&mhdr, 0, sizeof(mhdr));
        mhdr.msg_name = &whereto;
        mhdr.msg_namelen = sizeof(struct sockaddr_in6);
        mhdr.msg_iov = &iov;
        mhdr.msg_iovlen = 1;
        mhdr.msg_control = cmsgbuf;
        mhdr.msg_controllen = cmsglen;

        cc = sendmsg(sock->fd, &mhdr, a_ping_handle->ping_common.confirm);
    }
    a_ping_handle->ping_common.confirm = 0;

    return (cc == len ? 0 : cc);
}

void pr_echo_reply(uint8_t *_icmph, int cc __attribute__((__unused__)))
{
    struct icmp6_hdr *icmph = (struct icmp6_hdr *) _icmph;
    log_printf(" icmp_seq=%u", ntohs(icmph->icmp6_seq));
}

static void putchar_safe(char c)
{
    if(isprint(c))
        putchar(c);
    else
        printf("\\%03o", c);
}

static
void pr_niquery_reply_name(struct ni_hdr *nih, int len)
{
    uint8_t *h = (uint8_t *) (nih + 1);
    uint8_t *p = h + 4;
    uint8_t *end = (uint8_t *) nih + len;
    int continued = 0;
    char buf[1024];
    int ret;

    len -= sizeof(struct ni_hdr) + 4;

    if(len < 0) {
        printf(" parse error (too short)");
        return;
    }
    while(p < end) {
        int fqdn = 1;
        size_t i;

        memset(buf, 0xff, sizeof(buf));

        if(continued)
            putchar(',');

        ret = dn_expand(h, end, p, buf, sizeof(buf));
        if(ret < 0) {
            printf(" parse error (truncated)");
            break;
        }
        if(p + ret < end && *(p + ret) == '\0')
            fqdn = 0;

        putchar(' ');
        for(i = 0; i < strlen(buf); i++)
            putchar_safe(buf[i]);
        if(fqdn)
            putchar('.');

        p += ret + !fqdn;

        continued = 1;
    }
}

static
void pr_niquery_reply_addr(struct ni_hdr *nih, int len)
{
    uint8_t *h = (uint8_t *) (nih + 1);
    uint8_t *p;
    uint8_t *end = (uint8_t *) nih + len;
    int af;
    int aflen;
    int continued = 0;
    int truncated;
    char buf[1024];

    switch (ntohs(nih->ni_qtype)) {
        case NI_QTYPE_IPV4ADDR:
        af = AF_INET;
        aflen = sizeof(struct in_addr);
        truncated = nih->ni_flags & NI_IPV6ADDR_F_TRUNCATE;
        break;
        case NI_QTYPE_IPV6ADDR:
        af = AF_INET6;
        aflen = sizeof(struct in6_addr);
        truncated = nih->ni_flags & NI_IPV4ADDR_F_TRUNCATE;
        break;
        default:
        /* should not happen */
        af = aflen = truncated = 0;
    }
    p = h;
    if(len < 0) {
        printf(" parse error (too short)");
        return;
    }

    while(p < end) {
        if(continued)
            putchar(',');

        if(p + sizeof(uint32_t) + aflen > end) {
            printf(" parse error (truncated)");
            break;
        }
        if(!inet_ntop(af, p + sizeof(uint32_t), buf, sizeof(buf)))
            printf(" unexpeced error in inet_ntop(%s)",
                    strerror(errno));
        else
            printf(" %s", buf);
        p += sizeof(uint32_t) + aflen;

        continued = 1;
    }
    if(truncated)
        printf(" (truncated)");
}

static
void pr_niquery_reply(uint8_t *_nih, int len)
{
    struct ni_hdr *nih = (struct ni_hdr *) _nih;

    switch (nih->ni_code) {
    case NI_SUCCESS:
        switch (ntohs(nih->ni_qtype)) {
            case NI_QTYPE_NAME:
            pr_niquery_reply_name(nih, len);
            break;
            case NI_QTYPE_IPV4ADDR:
            case NI_QTYPE_IPV6ADDR:
            pr_niquery_reply_addr(nih, len);
            break;
            default:
            printf(" unknown qtype(0x%02x)", ntohs(nih->ni_qtype));
        }
        break;
        case NI_REFUSED:
        printf(" refused");
        break;
        case NI_UNKNOWN:
        printf(" unknown");
        break;
        default:
        printf(" unknown code(%02x)", ntohs(nih->ni_code));
    }
    printf("; seq=%u;", ntohsp((uint16_t*) nih->ni_nonce));
}

/*
 * parse_reply --
 *  Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
int
ping6_parse_reply(ping_handle_t *a_ping_handle, socket_st *sock, struct msghdr *msg, int cc, void *addr, struct timeval *tv)
{
    struct sockaddr_in6 *from = addr;
    uint8_t *buf = msg->msg_iov->iov_base;
    struct cmsghdr *c;
    struct icmp6_hdr *icmph;
    int hops = -1;

    for(c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
        if(c->cmsg_level != IPPROTO_IPV6)
            continue;
        switch (c->cmsg_type) {
        case IPV6_HOPLIMIT:
            #ifdef IPV6_2292HOPLIMIT
        case IPV6_2292HOPLIMIT:
            #endif
            if(c->cmsg_len < CMSG_LEN(sizeof(int)))
                continue;
            memcpy(&hops, CMSG_DATA(c), sizeof(hops));
        }
    }

    /* Now the ICMP part */

    icmph = (struct icmp6_hdr *) buf;
    if(cc < 8) {
        if(a_ping_handle->ping_common.options & F_VERBOSE)
            error(0, 0, "packet too short: %d bytes", cc);
        return 1;
    }

    if(icmph->icmp6_type == ICMP6_ECHO_REPLY) {
        if(!is_ours(a_ping_handle, sock, icmph->icmp6_id))
        return 1;
        if (!contains_pattern_in_payload(a_ping_handle, (uint8_t*)(icmph+1)))
        return 1; /* 'Twas really not our ECHO */
        if (gather_statistics(a_ping_handle, (uint8_t*)icmph, sizeof(*icmph), cc,
                ntohs(icmph->icmp6_seq),
                hops, 0, tv, pr_addr(a_ping_handle, from, sizeof *from),
                pr_echo_reply)) {
            fflush(stdout);
            return 0;
        }
    } else if (icmph->icmp6_type == ICMPV6_NI_REPLY) {
        struct ni_hdr *nih = (struct ni_hdr *)icmph;
        int seq = niquery_check_nonce(nih->ni_nonce);
        if (seq < 0)
        return 1;
        if (gather_statistics(a_ping_handle, (uint8_t*)icmph, sizeof(*icmph), cc,
                seq,
                hops, 0, tv, pr_addr(a_ping_handle, from, sizeof *from),
                pr_niquery_reply))
        return 0;
    } else {
        int nexthdr;
        struct ip6_hdr *iph1 = (struct ip6_hdr*)(icmph+1);
        struct icmp6_hdr *icmph1 = (struct icmp6_hdr *)(iph1+1);

        /* We must not ever fall here. All the messages but
         * echo reply are blocked by filter and error are
         * received with IPV6_RECVERR. Ugly code is preserved
         * however, just to remember what crap we avoided
         * using RECVRERR. :-)
         */

        if (cc < (int) (8 + sizeof(struct ip6_hdr) + 8))
        return 1;

        if (memcmp(&iph1->ip6_dst, &whereto.sin6_addr, 16))
        return 1;

        nexthdr = iph1->ip6_nxt;

        if (nexthdr == 44) {
            nexthdr = *(uint8_t*)icmph1;
            icmph1++;
        }
        if (nexthdr == IPPROTO_ICMPV6) {
            if (icmph1->icmp6_type != ICMP6_ECHO_REQUEST ||
            !is_ours(a_ping_handle, sock, icmph1->icmp6_id))
            return 1;
            acknowledge(a_ping_handle, ntohs(icmph1->icmp6_seq));
            a_ping_handle->ping_common.nerrors++;
            if (a_ping_handle->ping_common.options & F_FLOOD) {
                write_stdout("\bE", 2);
                return 0;
            }
            print_timestamp(a_ping_handle);
            printf("From %s: icmp_seq=%u ", pr_addr(a_ping_handle, from, sizeof *from), ntohs(icmph1->icmp6_seq));
        } else {
            /* We've got something other than an ECHOREPLY */
            if (!(a_ping_handle->ping_common.options & F_VERBOSE) || a_ping_handle->ping_common.uid)
            return 1;
            print_timestamp(a_ping_handle);
            printf("From %s: ", pr_addr(a_ping_handle, from, sizeof *from));
        }
        pr_icmph(icmph->icmp6_type, icmph->icmp6_code, ntohl(icmph->icmp6_mtu));
    }

    if(a_ping_handle->ping_common.options & F_AUDIBLE) {
        putchar('\a');
        if(a_ping_handle->ping_common.options & F_FLOOD)
            fflush(stdout);
    }
    if(!(a_ping_handle->ping_common.options & F_FLOOD)) {
        putchar('\n');
        fflush(stdout);
    }
    return 0;
}

int pr_icmph(uint8_t type, uint8_t code, uint32_t info)
{
    switch (type) {
    case ICMP6_DST_UNREACH:
        printf("Destination unreachable: ");
        switch (code) {
        case ICMP6_DST_UNREACH_NOROUTE:
            printf("No route");
            break;
        case ICMP6_DST_UNREACH_ADMIN:
            printf("Administratively prohibited");
            break;
        case ICMP6_DST_UNREACH_BEYONDSCOPE:
            printf("Beyond scope of source address");
            break;
        case ICMP6_DST_UNREACH_ADDR:
            printf("Address unreachable");
            break;
        case ICMP6_DST_UNREACH_NOPORT:
            printf("Port unreachable");
            break;
        default:
            printf("Unknown code %d", code);
            break;
        }
        break;
    case ICMP6_PACKET_TOO_BIG:
        printf("Packet too big: mtu=%u", info);
        if(code)
            printf(", code=%d", code);
        break;
    case ICMP6_TIME_EXCEEDED:
        printf("Time exceeded: ");
        if(code == ICMP6_TIME_EXCEED_TRANSIT)
            printf("Hop limit");
        else if(code == ICMP6_TIME_EXCEED_REASSEMBLY)
            printf("Defragmentation failure");
        else
            printf("code %d", code);
        break;
    case ICMP6_PARAM_PROB:
        printf("Parameter problem: ");
        if(code == ICMP6_PARAMPROB_HEADER)
            printf("Wrong header field ");
        else if(code == ICMP6_PARAMPROB_NEXTHEADER)
            printf("Unknown header ");
        else if(code == ICMP6_PARAMPROB_OPTION)
            printf("Unknown option ");
        else
            printf("code %d ", code);
        printf("at %u", info);
        break;
    case ICMP6_ECHO_REQUEST:
        printf("Echo request");
        break;
    case ICMP6_ECHO_REPLY:
        printf("Echo reply");
        break;
    case MLD_LISTENER_QUERY:
        printf("MLD Query");
        break;
    case MLD_LISTENER_REPORT:
        printf("MLD Report");
        break;
    case MLD_LISTENER_REDUCTION:
        printf("MLD Reduction");
        break;
    default:
        printf("unknown icmp type: %u", type);

    }
    return 0;
}

void ping6_install_filter(ping_handle_t *a_ping_handle, socket_st *sock)
{
    static int once;
    static struct sock_filter insns[] = {
    BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 4), /* Load icmp echo ident */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0xAAAA, 0, 1), /* Ours? */
    BPF_STMT(BPF_RET|BPF_K, ~0U), /* Yes, it passes. */
    BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 0), /* Load icmp type */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ICMP6_ECHO_REPLY, 1, 0), /* Echo? */
    BPF_STMT(BPF_RET|BPF_K, ~0U), /* No. It passes. This must not happen. */
    BPF_STMT(BPF_RET|BPF_K, 0), /* Echo with wrong ident. Reject. */
    };
    static struct sock_fprog filter = {
        sizeof insns / sizeof(insns[0]),
        insns
    };

    if(once)
        return;
    once = 1;

    /* Patch bpflet for current identifier. */
    insns[1] = (struct sock_filter )BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, htons(a_ping_handle->ping_common.ident), 0, 1);

    if(setsockopt(sock->fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)))
        error(0, errno, "WARNING: failed to install socket filter");
}
