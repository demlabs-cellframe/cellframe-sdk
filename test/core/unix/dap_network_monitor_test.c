#include <arpa/inet.h>
#include "linux/rtnetlink.h"

#include "dap_network_monitor.h"
#include "dap_network_monitor_test.h"

enum events {
    NEW_INTERFACE_EV,
    NEW_GATEWAY_EV,
    REMOVE_INTERFACE_EV,
    REMOVE_GATEWAY_EV,
    REMOVE_ROUTE_EV
};

#define COUNT_TEST_EVENT_CASES 5


static dap_network_notification_t _test_event_cases[COUNT_TEST_EVENT_CASES];


static bool list_events_done[COUNT_TEST_EVENT_CASES] = {0};

void _network_callback(const dap_network_notification_t result)
{
    if(result.type == IP_ADDR_ADD || result.type == IP_ADDR_REMOVE)
    {
        dap_test_msg("Interface %s %s has IP address %s",
               result.addr.interface_name, (result.type == IP_ADDR_ADD ? "now" : "no longer"),
               result.addr.s_ip);
        enum events event;
        if(result.type == IP_ADDR_ADD) {
            event = NEW_INTERFACE_EV;
        } else {
            event = REMOVE_INTERFACE_EV;
        }

        dap_test_msg("Checking %s" , (event == NEW_INTERFACE_EV ?
                                          "add new interface callback" : "remove interface callback"));

        dap_assert(result.addr.ip == _test_event_cases[event].addr.ip,
                   "Check dest ip");

        dap_assert(dap_str_equals(result.addr.s_ip, _test_event_cases[event].addr.s_ip),
                   "Check dest str ip");

        dap_assert(dap_str_equals(result.addr.interface_name,
                                  _test_event_cases[event].addr.interface_name),
                   "Check interface name");

        list_events_done[event] = true;

    } else if(result.type == IP_ROUTE_ADD || result.type == IP_ROUTE_REMOVE) {

        if (result.type == IP_ROUTE_REMOVE) {

            if(result.route.destination_address == _test_event_cases[REMOVE_GATEWAY_EV].route.gateway_address) {
                dap_pass_msg("Gateway addr removed");
                dap_assert(dap_str_equals(result.route.s_destination_address,
                                          _test_event_cases[REMOVE_GATEWAY_EV].route.s_gateway_address),
                           "Check gateway str ip");

                dap_assert(result.route.protocol == _test_event_cases[REMOVE_GATEWAY_EV].route.protocol,
                           "Check protocol");

                list_events_done[REMOVE_GATEWAY_EV] = true;
            } else if(result.route.destination_address ==
                      _test_event_cases[REMOVE_ROUTE_EV].route.destination_address) {
                dap_pass_msg("Destination address removed");

                dap_assert(dap_str_equals(result.route.s_destination_address,
                                          _test_event_cases[REMOVE_ROUTE_EV].route.s_destination_address),
                           "Check dest str ip");

                dap_assert(result.route.protocol == _test_event_cases[REMOVE_ROUTE_EV].route.protocol,
                           "Check protocol");

                list_events_done[REMOVE_ROUTE_EV] = true;
            }

//            dap_test_msg("Deleting route to destination --> %s/%d proto %d and gateway %s\n",
//                         result.route.s_destination_address,
//                         result.route.netmask,
//                         result.route.protocol,
//                         result.route.s_gateway_address);

        } else  if (result.type == IP_ROUTE_ADD) {
            if(result.route.gateway_address != (uint64_t) -1) { // gateway address is present
                dap_test_msg("Checking new gateway addr");
                dap_assert(result.route.gateway_address ==
                           _test_event_cases[NEW_GATEWAY_EV].route.gateway_address,
                           "Check gateway ip");

                dap_assert(dap_str_equals(result.route.s_gateway_address,
                                          _test_event_cases[NEW_GATEWAY_EV].route.s_gateway_address),
                           "Check gateway str ip");

                dap_assert(result.route.protocol == _test_event_cases[NEW_GATEWAY_EV].route.protocol,
                           "Check protocol");

                list_events_done[NEW_GATEWAY_EV] = true;
            }
//            dap_test_msg("Adding route to destination --> %s/%d proto %d and gateway %s\n",
//                         result.route.s_destination_address,
//                         result.route.netmask,
//                         result.route.protocol,
//                         result.route.s_gateway_address);
        }
    }
}


static void init_test_case()
{
    bzero(_test_event_cases, sizeof (_test_event_cases));

    dap_network_notification_t * res;

    // new_interface
    res = &_test_event_cases[NEW_INTERFACE_EV];
    res->type = IP_ADDR_ADD;
    strcpy(res->addr.s_ip, "10.1.0.111");
    strcpy(res->addr.interface_name, "tun10");
    res->addr.ip = 167837807;

    // new_gateway
    res = &_test_event_cases[NEW_GATEWAY_EV];
    res->type = IP_ROUTE_ADD;
    strcpy(res->route.s_gateway_address, "10.1.0.1");
    res->route.gateway_address = 167837697;
    res->route.protocol = RTPROT_STATIC;

    res = &_test_event_cases[REMOVE_GATEWAY_EV];
    res->type = IP_ROUTE_REMOVE;
    strcpy(res->route.s_gateway_address, "10.1.0.1");
    res->route.gateway_address = 167837697;
    res->route.protocol = RTPROT_STATIC;


    // remove interface
    res = &_test_event_cases[REMOVE_INTERFACE_EV];
    res->type = IP_ADDR_REMOVE;
    strcpy(res->addr.s_ip, "10.1.0.111");
    strcpy(res->addr.interface_name, "tun10");
    res->addr.ip = 167837807;

    // remote route
    res = &_test_event_cases[REMOVE_ROUTE_EV];
    res->type = IP_ROUTE_REMOVE;
    strcpy(res->route.s_destination_address, "10.1.0.111");
    res->route.destination_address = 167837807;
    res->route.protocol = RTPROT_KERNEL;
}

static void cleanup_test_case()
{

}

void dap_network_monitor_test_run(void)
{
    dap_print_module_name("dap_network_monitor");

    init_test_case();

    dap_network_monitor_init(_network_callback);

    const char *add_test_interfece = "sudo nmcli connection add type tun con-name "
                                     "DiveVPNTest autoconnect false ifname tun10 "
                                     "mode tun ip4 10.1.0.111 gw4 10.1.0.1";
    const char *up_test_interfece = "sudo nmcli connection up DiveVPNTest";
    const char *down_test_interfece = "sudo nmcli connection down DiveVPNTest";
    const char *delete_test_interfece = "sudo nmcli connection delete DiveVPNTest 2> /dev/null";

    system(delete_test_interfece);
    system(add_test_interfece);
    system(up_test_interfece);
    system(down_test_interfece);
    system(delete_test_interfece);

    for(int i = 0; i < COUNT_TEST_EVENT_CASES; i++) {
        if(list_events_done[i] == false) {
            dap_fail("Not all events were processed");
        }
    }

    dap_network_monitor_deinit();
    cleanup_test_case();
}
