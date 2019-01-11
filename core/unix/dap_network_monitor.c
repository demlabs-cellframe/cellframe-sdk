#include <linux/netlink.h>
#include <pthread.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#include "dap_network_monitor.h"
#include "dap_common.h"


#define LOG_TAG "dap_network_monitor"

static struct {
    int socket;
    pthread_t thread;
    dap_network_monitor_notification_callback_t callback;
} _net_notification;

static void* network_monitor_worker(void *arg);

int dap_network_monitor_init(dap_network_monitor_notification_callback_t cb)
{
    memset((void*)&_net_notification, 0, sizeof(_net_notification));

    if ((_net_notification.socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1) {
        log_it(L_ERROR, "Can't open notification socket");
        return -1;
    }

    struct sockaddr_nl addr = {0};
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
    if (bind(_net_notification.socket, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        log_it(L_ERROR, "Can't bind notification socket");
        return -2;
    }

    pthread_barrier_t barrier;

    pthread_barrier_init(&barrier, NULL, 2);
    if(pthread_create(&_net_notification.thread, NULL, network_monitor_worker, &barrier) != 0) {
        log_it(L_ERROR, "Error create notification thread");
        return -3;
    }

    pthread_barrier_wait(&barrier);

    pthread_barrier_destroy(&barrier);

    _net_notification.callback = cb;
    log_it(L_DEBUG, "dap_network_monitor was initialized");
    return 0;
}

void dap_network_monitor_deinit(void)
{
    if(_net_notification.socket == 0 || _net_notification.socket == -1) {
        log_it(L_ERROR, "Network monitor not be inited");
        return;
    }
    close(_net_notification.socket);
    pthread_cancel(_net_notification.thread);
    pthread_join(_net_notification.thread, NULL);
}

static void _ip_addr_msg_handler(struct nlmsghdr *nlh,
                                 dap_network_notification_t* result)
{
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
    struct rtattr *rth = IFA_RTA(ifa);
    size_t rtl = IFA_PAYLOAD(nlh);
    for (; rtl && RTA_OK(rth, rtl); rth = RTA_NEXT(rth,rtl)) {
        char *inet_str = inet_ntoa(*((struct in_addr *)RTA_DATA(rth)));

        if (rth->rta_type != IFA_LOCAL) continue;

        /* fill result */
        result->addr.ip = htonl(*((uint32_t *)RTA_DATA(rth)));
        strcpy(result->addr.s_ip, inet_str);
        if_indextoname(ifa->ifa_index, result->addr.interface_name);
    }
}

static void _route_msg_handler(struct nlmsghdr *nlh,
                               dap_network_notification_t* result,
                               int received_bytes)
{
    struct  rtmsg *route_entry;  /* This struct represent a route entry
                                        in the routing table */
    struct  rtattr *route_attribute; /* This struct contain route
                                                attributes (route type) */
    int     route_attribute_len = 0;

    route_attribute_len = RTM_PAYLOAD(nlh);

    for ( ; NLMSG_OK(nlh, received_bytes); \
                       nlh = NLMSG_NEXT(nlh, received_bytes))
       {
           /* Get the route data */
           route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

           result->route.netmask = route_entry->rtm_dst_len;
           result->route.protocol = route_entry->rtm_protocol;

           /* Get attributes of route_entry */
           route_attribute = (struct rtattr *) RTM_RTA(route_entry);

           /* Get the route atttibutes len */
           route_attribute_len = RTM_PAYLOAD(nlh);
           /* Loop through all attributes */
           for ( ; RTA_OK(route_attribute, route_attribute_len); \
               route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
           {
               /* Get the destination address */
               if (route_attribute->rta_type == RTA_DST)
               {
                   result->route.destination_address = htonl(*(uint32_t*)RTA_DATA(route_attribute));

                   inet_ntop(AF_INET, RTA_DATA(route_attribute),
                                                result->route.s_destination_address,
                                                sizeof(result->route.s_destination_address));
               }
               /* Get the gateway (Next hop) */
               if (route_attribute->rta_type == RTA_GATEWAY)
               {
                   result->route.gateway_address = htonl(*(uint32_t*)RTA_DATA(route_attribute));
;
                   inet_ntop(AF_INET, RTA_DATA(route_attribute),
                                                result->route.s_gateway_address,
                                                sizeof(result->route.s_gateway_address));
               }
           }
   }

}

static void clear_results(dap_network_notification_t* cb_result) {
    bzero(cb_result, sizeof (dap_network_notification_t));
    cb_result->route.destination_address = (uint64_t) -1;
    cb_result->route.gateway_address = (uint64_t) -1;
}

static void* network_monitor_worker(void *arg)
{
    pthread_barrier_t *barrier = (pthread_barrier_t *)arg;
    log_it(L_DEBUG, "Network monitor worker started");
    if (_net_notification.socket == -1) {
        log_it(L_ERROR, "Net socket not running. Can't start worker");
        return  NULL;
    }

    char buffer[4096];
    dap_network_notification_t callback_result;

    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
    int len;

    pthread_barrier_wait(barrier);

    while ((len = recv(_net_notification.socket, nlh, sizeof(buffer), 0)) > 0) {
        for (; (NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE); nlh = NLMSG_NEXT(nlh, len)) {

            clear_results(&callback_result);

            callback_result.type = nlh->nlmsg_type;
            if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
                _ip_addr_msg_handler(nlh, &callback_result);
            } else if(nlh->nlmsg_type == RTM_NEWROUTE || nlh->nlmsg_type == RTM_DELROUTE) {
                _route_msg_handler(nlh, &callback_result, len);
            } else {
                log_it(L_DEBUG, "Not supported msg type %d", nlh->nlmsg_type);
                continue;
            }

            if (_net_notification.callback) {
                _net_notification.callback(callback_result);
            } else {
                log_it(L_ERROR, "callback is NULL");
            }
        }
    }
}
