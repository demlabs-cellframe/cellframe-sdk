#include <dap_chain_node_cli.h>
#include "dap_chain_node_cli_cmd.h"
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
        CMD_NONE, CMD_INIT, CMD_START, CMD_STOP, CMD_STATUS
    };
    int l_arg_index = 1;
    // find net
    dap_chain_net_t *l_net = NULL;
    if(dap_chain_node_cli_cmd_values_parse_net_chain(&l_arg_index, a_argc, a_argv, a_str_reply, NULL, &l_net) < 0)
        return -2;

    int cmd_num = CMD_NONE;
    if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "init", NULL)) {
        cmd_num = CMD_INIT;
    }
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
    case CMD_INIT: {
            const char * l_str_token = NULL; // token name
            const char * l_str_value_datoshi = NULL;
            const char * l_str_wallet = NULL; // wallet name
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_str_wallet);
            if(!l_str_wallet)
                dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_str_wallet);

            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_str_token);
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_str_value_datoshi);

            if(!l_str_wallet) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Wallet not defined, use -w <wallet_name> or -wallet <wallet_name> parameter");
                break;
            }
            if(!l_str_token) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Token not defined, use -token <token_name> parameter");
                break;
            }
            if(!l_str_value_datoshi) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Value of datoshi not defined, use -value <value of datoshi> parameter");
                break;
            }
            uint64_t l_a_value_datoshi = strtoull(l_str_value_datoshi, NULL, 10);
            if(!l_a_value_datoshi)
                l_a_value_datoshi = strtoull(l_str_value_datoshi, NULL, 16);
            if(!l_a_value_datoshi) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Value of datoshi have to be more then 0");
                break;
            }
            int l_res = dap_chain_net_vpn_client_update(l_net, l_str_wallet, l_str_token, l_a_value_datoshi);
            if(!l_res)
                dap_chain_node_cli_set_reply_text(a_str_reply, "VPN client init successfully");
            else{
                if(l_res==-3)
                    dap_chain_node_cli_set_reply_text(a_str_reply, "VPN client init successfully, but probably not enough founds in the wallet");
                else
                    dap_chain_node_cli_set_reply_text(a_str_reply, "VPN client not init");
            }
            return l_res;
    }
        break;
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
        break;
    case CMD_STATUS:
        {
        char *l_wallet_name = NULL, *l_str_token = NULL;
        uint64_t l_value_datoshi = 0;
        dap_chain_net_vpn_client_get_wallet_info(l_net, &l_wallet_name, &l_str_token, &l_value_datoshi);

        const char *l_status_txt = "";
        switch (dap_chain_net_vpn_client_status()) {
        case VPN_CLIENT_STATUS_NOT_STARTED:
            l_status_txt = "VPN client not started";
            break;
        case VPN_CLIENT_STATUS_STARTED:
            l_status_txt = "VPN client started";
            break;
        case VPN_CLIENT_STATUS_STOPPED:
            l_status_txt = "VPN client stopped";
            break;
        case VPN_CLIENT_STATUS_CONN_LOST:
            l_status_txt = "VPN client lost connection";
            break;
        default:
            l_status_txt = "VPN client status unknown";
            break;
        }
        dap_chain_node_cli_set_reply_text(a_str_reply, "%s\nused:\nwallet:%s\nreceipt:%u*1e-9 %s", l_status_txt,
                l_wallet_name, l_value_datoshi, l_str_token);
        break;
    }
    }
#endif
    return 0;
}


int dap_chain_net_srv_vpn_cmd_init()
{


}
