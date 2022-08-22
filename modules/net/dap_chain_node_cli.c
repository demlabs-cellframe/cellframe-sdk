/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe  https://cellframe.net
 * Copyright  (c) 2019-2021
 * All rights reserved.

 This file is part of Cellframe SDK

 Cellframe SDK is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Cellframe SDK is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
//#include <glib.h>
#include <unistd.h>


#include <pthread.h>

#include "iputils/iputils.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_list.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_cli_cmd_tx.h"
#include "dap_cli_server.h"
#include "dap_chain_node_cli.h"

//#include "dap_chain_node_cli.h"

#define LOG_TAG "chain_node_cli"
static bool s_debug_cli = false;

/**
 * @brief dap_chain_node_cli_init
 * Initialization of the server side of the interaction
 * with the console kelvin-node-cli
 * init commands description
 * return 0 if OK, -1 error
 * @param g_config
 * @return int
 */
int dap_chain_node_cli_init(dap_config_t * g_config)
{
    s_debug_cli = dap_config_get_item_bool_default(g_config,"conserver","debug_cli",false);

    bool l_conserver_enabled = dap_config_get_item_bool_default( g_config, "conserver", "enabled", true );

    if ( !l_conserver_enabled ) {

        log_it( L_WARNING, "Console Server is dissabled." );
        return 0;
    }

#ifdef __WIN32
    WSADATA wsaData;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        log_it(L_CRITICAL, "Couldn't init Winsock DLL, error: %d", ret);
        return 2;
    }
#endif
    uint16_t l_listen_port = dap_config_get_item_uint16_default( g_config, "conserver", "listen_port_tcp",0); // For backward compatibility
    if(l_listen_port == 0)
        l_listen_port = dap_config_get_item_uint16_default( g_config, "conserver", "listen_port",0);

    dap_cli_server_init( s_debug_cli,
                         l_listen_port ? dap_config_get_item_str(g_config, "conserver", "listen_address")
                                       : dap_config_get_item_str( g_config, "conserver", "listen_unix_socket_path"),
                         l_listen_port, dap_config_get_item_str( g_config, "conserver", "listen_unix_socket_permissions")
                        );

    dap_cli_server_cmd_add("global_db", com_global_db, "Work with global database",
            "global_db cells add -cell <cell id> \n"
            "global_db flush \n\n"
//                    "global_db wallet_info set -addr <wallet address> -cell <cell id> \n\n"
            );
    dap_cli_server_cmd_add("mempool", com_signer, "Sign operations",
               "mempool sign -cert <cert name> -net <net name> -chain <chain name> -file <filename> [-mime {<SIGNER_FILENAME,SIGNER_FILENAME_SHORT,SIGNER_FILESIZE,SIGNER_DATE,SIGNER_MIME_MAGIC> | <SIGNER_ALL_FLAGS>}]\n"
               "mempool check -cert <cert name> -net <net name> {-file <filename> | -hash <hash>} [-mime {<SIGNER_FILENAME,SIGNER_FILENAME_SHORT,SIGNER_FILESIZE,SIGNER_DATE,SIGNER_MIME_MAGIC> | <SIGNER_ALL_FLAGS>}]\n"
                                          );
    dap_cli_server_cmd_add("node", com_node, "Work with node",
            "node add  -net <net name> {-addr <node address> | -alias <node alias>} -port <port> -cell <cell id>  {-ipv4 <ipv4 external address> | -ipv6 <ipv6 external address>}\n\n"
                    "node del -net <net name> {-addr <node address> | -alias <node alias>}\n\n"
                    "node link {add | del}  -net <net name> {-addr <node address> | -alias <node alias>} -link <node address>\n\n"
                    "node alias -addr <node address> -alias <node alias>\n\n"
                    "node connect -net <net name> {-addr <node address> | -alias <node alias> | auto}\n\n"
                    "node handshake -net <net name> {-addr <node address> | -alias <node alias>}\n"
                    "node dump -net <net name> [ -addr <node address> | -alias <node alias>] [-full]\n\n"
                                        );
    dap_cli_server_cmd_add ("ping", com_ping, "Send ICMP ECHO_REQUEST to network hosts",
            "ping [-c <count>] host\n");
    dap_cli_server_cmd_add ("traceroute", com_traceroute, "Print the hops and time of packets trace to network host",
            "traceroute host\n");
    dap_cli_server_cmd_add ("tracepath", com_tracepath,"Traces path to a network host along this path",
            "tracepath host\n");
    dap_cli_server_cmd_add ("version", com_version, "Return software version",
                                        "version\n"
                                        "\tReturn version number\n"
                                        );

    dap_cli_server_cmd_add ("help", com_help, "Description of command parameters",
                                        "help [<command>]\n"
                                        "\tObtain help for <command> or get the total list of the commands\n"
                                        );
    dap_cli_server_cmd_add ("?", com_help, "Synonym for \"help\"",
                                        "? [<command>]\n"
                                        "\tObtain help for <command> or get the total list of the commands\n"
                                        );
    dap_cli_server_cmd_add("wallet", com_tx_wallet, "Wallet operations",
            "wallet {new -w <wallet_name> [-sign <sign_type>] [-restore <hex value>] [-net <net_name>] [-force]| list | info {-addr <addr> | -w <wallet_name>} -net <net_name>}\n");

    // Token commands
    dap_cli_server_cmd_add ("token_update", com_token_update, "Token update",
            "\nPrivate token update\n"
            "token_update -net <net name> -chain <chain name> -token <token ticker> [-type private] [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
            "\t   Update private token <token ticker> for <netname>:<chain name> with"
            "\t   custom parameters list <Param 1>, <Param 2>...<Param N>."
            "\n"
            "==Params==\n"
            "General:\n"
            "\t -flags_set <value>:\t Set list of flags from <value> to token declaration\n"
            "\t -flags_unset <value>:\t Unset list of flags from <value> from token declaration\n"
            "\t -total_supply <value>:\t Set total supply - emission's maximum - to the <value>\n"
            "\t -total_signs_valid <value>:\t Set valid signatures count's minimum\n"
            "\t -signs_add <value>:\t Add signature's pkey fingerprint to the list of owners\n"
            "\t -signs_remove <value>:\t Remove signature's pkey fingerprint from the owners\n"
            "\nDatum type allowed/blocked updates:\n"
            "\t -datum_type_allowed_add <value>:\t Add allowed datum type(s)\n"
            "\t -datum_type_allowed_remove <value>:\t Remove datum type(s) from allowed\n"
            "\t -datum_type_allowed_clear:\t Remove all datum types from allowed\n"
            "\t -datum_type_blocked_add <value>:\t Add blocked datum type(s)\n"
            "\t -datum_type_blocked_remove <value>:\t Remove datum type(s) from blocked\n"
            "\t -datum_type_blocked_clear:\t Remove all datum types from blocked\n"
            "\nTx receiver addresses allowed/blocked updates:\n"
            "\t -tx_receiver_allowed_add <value>:\t Add allowed tx receiver(s)\n"
            "\t -tx_receiver_allowed_remove <value>:\t Remove tx receiver(s) from allowed\n"
            "\t -tx_receiver_allowed_clear:\t Remove all tx receivers from allowed\n"
            "\t -tx_receiver_blocked_add <value>:\t Add blocked tx receiver(s)\n"
            "\t -tx_receiver_blocked_remove <value>:\t Remove tx receiver(s) from blocked\n"
            "\t -tx_receiver_blocked_clear:\t Remove all tx receivers from blocked\n"
            "\nTx sender addresses allowed/blocked updates:\n"
            "\t -tx_sender_allowed_add <value>:\t Add allowed tx sender(s)\n"
            "\t -tx_sender_allowed_remove <value>:\t Remove tx sender(s) from allowed\n"
            "\t -tx_sender_allowed_clear:\t Remove all tx senders from allowed\n"
            "\t -tx_sender_blocked_add <value>:\t Add allowed tx sender(s)\n"
            "\t -tx_sender_blocked_remove <value>:\t Remove tx sender(s) from blocked\n"
            "\t -tx_sender_blocked_clear:\t Remove all tx sender(s) from blocked\n"
            "\n"
            "==Flags=="
            "\t ALL_BLOCKED:\t Blocked all permissions, usefull add it first and then add allows what you want to allow\n"
            "\t ALL_ALLOWED:\t Allowed all permissions if not blocked them. Be careful with this mode\n"
            "\t ALL_FROZEN:\t All permissions are temprorary frozen\n"
            "\t ALL_UNFROZEN:\t Unfrozen permissions\n"
            "\t STATIC_ALL:\t No token manipulations after declarations at all. Token declares staticly and can't variabed after\n"
            "\t STATIC_FLAGS:\t No token manipulations after declarations with flags\n"
            "\t STATIC_PERMISSIONS_ALL:\t No all permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_DATUM_TYPE:\t No datum type permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_TX_SENDER:\t No tx sender permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_TX_RECEIVER:\t No tx receiver permissions lists manipulations after declarations\n"
            "\n"
            );
    // Token commands
    dap_cli_server_cmd_add ("token_decl", com_token_decl, "Token declaration",
            "Simple token declaration:\n"
            "\t token_decl -net <net name> -chain <chain name> -token <token ticker> -total_supply <total supply> -signs_total <sign total> -signs_emission <signs for emission> -certs <certs list>\n"
            "\t  Declare new simple token for <netname>:<chain name> with ticker <token ticker>, maximum emission <total supply> and <signs for emission> from <signs total> signatures on valid emission\n"
            "\nExtended private token declaration\n"
            "\t token_decl -net <net name> -chain <chain name> -token <token ticker> -type private -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...\n"
            "\t [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
            "\t   Declare new token for <netname>:<chain name> with ticker <token ticker>, flags <Flag 1>,<Flag2>...<Flag N>\n"
            "\t   and custom parameters list <Param 1>, <Param 2>...<Param N>.\n"
            "\nExtended CF20 token declaration\n"
            "\t token_decl -net <net name> -chain <chain name> -token <token ticker> -type CF20 -decimals <18> -signs_total <sign total> -signs_emission <signs for emission> -certs <certs list>"
            "\t -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...\n"
            "\t [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
            "\t   Declare new token for <netname>:<chain name> with ticker <token ticker>, flags <Flag 1>,<Flag2>...<Flag N>\n"
            "\t   and custom parameters list <Param 1>, <Param 2>...<Param N>.\n"
            "\n"
            "==Flags=="
            "\t ALL_BLOCKED:\t Blocked all permissions, usefull add it first and then add allows what you want to allow\n"
            "\t ALL_ALLOWED:\t Allowed all permissions if not blocked them. Be careful with this mode\n"
            "\t ALL_FROZEN:\t All permissions are temprorary frozen\n"
            "\t ALL_UNFROZEN:\t Unfrozen permissions\n"
            "\t STATIC_ALL:\t No token manipulations after declarations at all. Token declares staticly and can't variabed after\n"
            "\t STATIC_FLAGS:\t No token manipulations after declarations with flags\n"
            "\t STATIC_PERMISSIONS_ALL:\t No all permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_DATUM_TYPE:\t No datum type permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_TX_SENDER:\t No tx sender permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_TX_RECEIVER:\t No tx receiver permissions lists manipulations after declarations\n"
            "\n"
            "==Params==\n"
            "General:\n"
            "\t -flags <value>:\t List of flags from <value> to token declaration\n"
            "\t -total_supply <value>:\t Set total supply - emission's maximum - to the <value>\n"
            "\t -total_signs_valid <value>:\t Set valid signatures count's minimum\n"
            "\t -signs <value>:\t Signature's fingerprint list\n"
            "\nDatum type allowed/blocked:\n"
            "\t -datum_type_allowed <value>:\t Set allowed datum type(s)\n"
            "\t -datum_type_blocked <value>:\t Set blocked datum type(s)\n"
            "\nTx receiver addresses allowed/blocked:\n"
            "\t -tx_receiver_allowed <value>:\t Set allowed tx receiver(s)\n"
            "\t -tx_receiver_blocked <value>:\t Set blocked tx receiver(s)\n"
            "\nTx sender addresses allowed/blocked:\n"
            "\t -tx_sender_allowed <value>:\t Set allowed tx sender(s)\n"
            "\t -tx_sender_blocked <value>:\t Set allowed tx sender(s)\n"
            "\n"
            );

    dap_cli_server_cmd_add ("token_decl_sign", com_token_decl_sign, "Token declaration add sign",
            "token_decl_sign -net <net name> -chain <chain name> -datum <datum_hash> -certs <certs list>\n"
            "\t Sign existent <datum hash> in mempool with <certs list>\n"
            );

    dap_cli_server_cmd_add ("token_emit", com_token_emit, "Token emission",
            "token_emit {sign | -token <token ticker> -emission_value <val>} -net <net name> [-chain_emission <chain for emission>] [-chain_base_tx <chain for base tx> -addr <addr>] -certs <cert list>\n");

    dap_cli_server_cmd_add ("mempool_list", com_mempool_list, "List mempool entries for selected chain network",
            "mempool_list -net <net name>\n");

    dap_cli_server_cmd_add ("mempool_proc", com_mempool_proc, "Proc mempool entrie with specified hash for selected chain network",
            "mempool_proc -net <net name> -datum <datum hash>\n");

    dap_cli_server_cmd_add ("mempool_delete", com_mempool_delete, "Delete datum with hash <datum hash> for selected chain network",
            "mempool_delete -net <net name> -datum <datum hash>\n");

    dap_cli_server_cmd_add ("mempool_add_ca", com_mempool_add_ca,
                                        "Add pubic certificate into the mempool to prepare its way to chains",
            "mempool_add_ca -net <net name> [-chain <chain name>] -ca_name <Certificate name>\n");

    dap_cli_server_cmd_add ("chain_ca_pub", com_chain_ca_pub,
                                        "Add pubic certificate into the mempool to prepare its way to chains",
            "chain_ca_pub -net <net name> [-chain <chain name>] -ca_name <Certificate name>\n");

    dap_cli_server_cmd_add ("chain_ca_copy", com_chain_ca_copy,
                                        "Copy pubic certificate into the mempool to prepare its way to chains",
            "chain_ca_copy -net <net name> [-chain <chain name>] -ca_name <Public certificate name>\n");

    // Transaction commands
    dap_cli_server_cmd_add ("tx_create", com_tx_create, "Make transaction",
            "tx_create -net <net name> -chain <chain name> {-from_wallet <name> -token <token ticker> -value <value> -to_addr <addr> | -from_emission <emission_hash>} [-fee <addr> -value_fee <val>]\n" );
    dap_cli_server_cmd_add ("tx_create_json", com_tx_create_json, "Make transaction",
                "tx_create_json -net <net name> -chain <chain name> -json <json file path>\n" );
    dap_cli_server_cmd_add ("tx_cond_create", com_tx_cond_create, "Make cond transaction",
                                        "tx_cond_create -net <net name> -token <token ticker> -wallet <from wallet> -cert <public cert> -value <value datoshi> -unit {mb | kb | b | sec | day} -srv_uid <numeric uid>\n" );

    dap_cli_server_cmd_add ("tx_verify", com_tx_verify, "Verifing transaction in mempool",
            "tx_verify -net <net name> -chain <chain name> -tx <tx_hash>\n" );

    // Transaction history
    dap_cli_server_cmd_add("tx_history", com_tx_history, "Transaction history (for address or by hash)",
            "tx_history  {-addr <addr> | -w <wallet name> | -tx <tx_hash>} -net <net name> -chain <chain name>\n");

    // Ledger info
    dap_cli_server_cmd_add("ledger", com_ledger, "Ledger information",
            "ledger list coins -net <network name>\n"
            "ledger list threshold [-hash <tx_treshold_hash>] -net <network name>\n"
            "ledger list balance -net <network name>\n"
            "ledger info -hash <tx_hash> -net <network name> [-unspent]\n"
            "ledger tx -all -net <network name>\n"
            "ledger tx {-addr <addr> | -w <wallet name> | -tx <tx_hash>} [-chain <chain name>] -net <network name>\n");

    // Token info
    dap_cli_server_cmd_add("token", com_token, "Token info",
            "token list -net <network name>\n"
            "token info -net <network name> -name <token name>\n"
            "token tx [all | -addr <wallet_addr> | -wallet <wallet_name>] -name <token name> -net <network name> [-page_start <page>] [-page <page>]\n");

    // Log
    dap_cli_server_cmd_add ("print_log", com_print_log, "Print log info",
                "print_log [ts_after <timestamp >] [limit <line numbers>]\n" );

    // Statisticss
    dap_cli_server_cmd_add("stats", com_stats, "Print statistics",
                "stats cpu");



    // Exit
    dap_cli_server_cmd_add ("exit", com_exit, "Stop application and exit",
                "exit\n" );

     // Export GDB to JSON
     dap_cli_server_cmd_add("gdb_export", cmd_gdb_export, "Export gdb to JSON",
                                        "gdb_export filename <filename without extension> [-groups <group names list>]");

     //Import GDB from JSON
     dap_cli_server_cmd_add("gdb_import", cmd_gdb_import, "Import gdb from JSON",
                                        "gdb_import filename <filename without extension>");


    return 0;
}


/**
 * @brief dap_chain_node_cli_delete
 * Deinitialization of the server side
 */
void dap_chain_node_cli_delete(void)
{
    dap_cli_server_deinit();
    // deinit client for handshake
    dap_chain_node_client_deinit();
}
