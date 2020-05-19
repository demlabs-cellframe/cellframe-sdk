#include <dap_chain_node_cli.h>
#include "dap_chain_net_srv_vpn_cmd.h"
#include "dap_chain_net_vpn_client.h"


/**
 * vpn_client command
 *
 * VPN client control
 */
int com_vpn_client(int a_argc, char ** a_argv, void *arg_func, char **a_str_reply)
{
#ifndef _WIN32
    enum {
        CMD_NONE, CMD_START, CMD_STOP, CMD_STATUS
    };
    int l_arg_index = 1;
    // find net
    dap_chain_net_t *l_net = NULL;
    if(dap_chain_node_cli_cmd_values_parse_net_chain(&l_arg_index, a_argc, a_argv, a_str_reply, NULL, &l_net) < 0)
        return -2;

    int cmd_num = CMD_NONE;
    if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "start", NULL)) {
        cmd_num = CMD_START;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "stop", NULL)) {
        cmd_num = CMD_STOP;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "status", NULL)) {
        cmd_num = CMD_STATUS;
    }
    if(cmd_num == CMD_NONE) {
        if(!a_argv[1])
            dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameters");
        else
            dap_chain_node_cli_set_reply_text(a_str_reply, "parameter %s not recognized", a_argv[1]);
        return -1;
    }

    switch (cmd_num)
    {
    case CMD_START: {
        const char * l_str_addr = NULL; // for example, "192.168.100.93"
        const char * l_str_port = NULL; // for example, "8079"
        dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_str_addr);
        if(!l_str_addr) {
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "VPN server address not defined, use -addr <vpn server ipv4 address> parameter");
            break;
        }
        dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-port", &l_str_port);
        int l_srv_port = (l_str_port) ? (int) strtoll(l_str_port, 0, 10) : 0;
        if(!l_srv_port) {
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "VPN server port not defined, use -port <vpn server port>  parameter");
            break;
        }
        int l_res = dap_chain_net_vpn_client_start(l_net, l_str_addr, NULL, l_srv_port);
        switch (l_res) {
        case 0:
            dap_chain_node_cli_set_reply_text(a_str_reply, "VPN client started successfully");
            break;
        case 1:
            dap_chain_node_cli_set_reply_text(a_str_reply, "VPN client already started");
            break;
        case -2:
        case -3:
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't connect to VPN server");
            break;
        default:
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't start VPN client");
            break;
        }
        return l_res;
    }
        break;
    case CMD_STOP: {
        int res = dap_chain_net_vpn_client_stop();
        if(!res)
            dap_chain_node_cli_set_reply_text(a_str_reply, "VPN client stopped successfully");
        else
            dap_chain_node_cli_set_reply_text(a_str_reply, "VPN client not stopped");
        return res;
    }
        //break;
    case CMD_STATUS:
        switch (dap_chain_net_vpn_client_status()) {
//        switch (0){
        case 0:
            dap_chain_node_cli_set_reply_text(a_str_reply, "VPN client stopped");
            return 0;
        case 1:
            dap_chain_node_cli_set_reply_text(a_str_reply, "VPN client started");
            return 0;
        case -1:
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't get VPN state");
            return -1;
        }
        break;
    }
#endif
    return 0;
}


int dap_chain_net_srv_vpn_cmd_init()
{
    dap_chain_node_cli_cmd_item_create ("vpn_client", com_vpn_client, NULL, "VPN client control",
    "vpn_client [start -addr <server address> -port <server port>| stop | status]\n");

    return 0;
}
