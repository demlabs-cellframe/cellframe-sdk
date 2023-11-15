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
            "global_db write -group <group_name> -key <key_name> -value <value>"
            "global_db read -group <group_name> -key <key_name>"
            "global_db delete -group <group_name> -key <key_name>"
            "global_db drop_table -group <group_name>\n"
            "global_db get_keys -group <group name>"

//                    "global_db wallet_info set -addr <wallet address> -cell <cell id> \n\n"
            );
    dap_cli_server_cmd_add("mempool", com_signer, "Sign operations",
               "mempool sign -cert <priv_cert_name> -net <net_name> -chain <chain_name> -file <filename> [-mime {<SIGNER_FILENAME,SIGNER_FILENAME_SHORT,SIGNER_FILESIZE,SIGNER_DATE,SIGNER_MIME_MAGIC> | <SIGNER_ALL_FLAGS>}]\n"
               "mempool check -cert <priv_cert_name> -net <net_name> {-file <filename> | -hash <hash>} [-mime {<SIGNER_FILENAME,SIGNER_FILENAME_SHORT,SIGNER_FILESIZE,SIGNER_DATE,SIGNER_MIME_MAGIC> | <SIGNER_ALL_FLAGS>}]\n"
                                          );
    dap_cli_server_cmd_add("node", com_node, "Work with node",
                    "node add  -net <net_name> -port <port> -ipv4 <ipv4 external address>\n\n"
                    "node del -net <net_name> {-addr <node_address> | -alias <node_alias>}\n\n"
                    "node link {add | del}  -net <net_name> {-addr <node_address> | -alias <node_alias>} -link <node_address>\n\n"
                    "node alias -addr <node_address> -alias <node_alias>\n\n"
                    "node connect -net <net_name> {-addr <node_address> | -alias <node_alias> | auto}\n\n"
                    "node handshake -net <net_name> {-addr <node_address> | -alias <node_alias>}\n"
                    "node connections -net <net_name>\n"
                    "node balancer -net <net_name>\n"
                    "node dump -net <net_name> [ -addr <node_address> | -alias <node_alias>] [-full]\n\n"
                                        );
    #ifndef DAP_OS_ANDROID
    dap_cli_server_cmd_add ("ping", com_ping, "Send ICMP ECHO_REQUEST to network hosts",
            "ping [-c <count>] host\n");
    dap_cli_server_cmd_add ("traceroute", com_traceroute, "Print the hops and time of packets trace to network host",
            "traceroute host\n");
    dap_cli_server_cmd_add ("tracepath", com_tracepath,"Traces path to a network host along this path",
            "tracepath host\n");
    #endif
    
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
    dap_cli_server_cmd_add ("wallet", com_tx_wallet, "Wallet operations",
                            "wallet list\n"
                            "wallet new -w <wallet_name> [-sign <sign_type>] [-restore <hex_value> | -restore_legacy <restore_string>] [-net <net_name>] [-force] [-password <password>]\n"
                            "wallet info {-addr <addr> | -w <wallet_name>} -net <net_name>\n"
                            "wallet activate -w <wallet_name> -password <password> [-ttl <password_ttl_in_minutes>]\n"
                            "wallet deactivate -w <wallet_name> -password <password>\n"
                            "wallet convert -w <wallet_name> -password <password>\n");


    // Token commands
    dap_cli_server_cmd_add ("token_update", com_token_update, "Token update",
                            "\nPrivate or CF20 token update\n"
                            "\nPrivate token update\n"
                            "token_update -net <net_name> -chain <chain_name> -token <existing token_ticker> -type private -total_supply <the same or more> -decimals <18>\n"
                            "-signs_total <the same total as the token you are updating> -signs_emission <the same total as the token you are updating> -certs <use the certificates of the token you are update>\n"
                            "-flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...\n"
                            "\t [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
                            "\t   Update token for <netname>:<chain name> with ticker <token ticker>, flags <Flag 1>,<Flag2>...<Flag N>\n"
                            "\t   and custom parameters list <Param 1>, <Param 2>...<Param N>.\n"
                            "\nCF20 token update\n"
                            "token_update -net <net_name> -chain <chain_name> -token <existing token_ticker> -type CF20 -total_supply <the same or more/if 0 = endless> -decimals <18>\n"
                            "-signs_total <the same total as the token you are updating> -signs_emission <the same total as the token you are updating> -certs <use the certificates of the token you are update>\n"
                            "\t -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...\n"
                            "\t [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
                            "\t   Update token for <netname>:<chain name> with ticker <token ticker>, flags <Flag 1>,<Flag2>...<Flag N>\n"
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
                            "\t -flags <value>:\t List of flags from <value> to token declaration or update\n"
                            "\t -total_supply <value>:\t Set total supply - emission's maximum - to the <value>\n"
                            "\t -total_signs_valid <value>:\t Set valid signatures count's minimum\n"
                            "\t -description <value>:\t Updated description for this token\n"
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


    // Token commands
    dap_cli_server_cmd_add ("token_decl", com_token_decl, "Token declaration",
            "Simple token declaration:\n"
            "token_decl -net <net_name> -chain <chain_name> -token <token_ticker> -total_supply <total supply> -signs_total <sign total> -signs_emission <signs for emission> -certs <certs list>\n"
            "\t  Declare new simple token for <netname>:<chain_name> with ticker <token_ticker>, maximum emission <total supply> and <signs for emission> from <signs total> signatures on valid emission\n"
            "\nExtended private token declaration\n"
            "token_decl -net <net_name> -chain <chain_name> -token <token_ticker> -type private -total_supply <total supply> "
                "-decimals <18> -signs_total <sign total> -signs_emission <signs for emission> -certs <certs list> -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...\n"
            "\t [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
            "\t   Declare new token for <netname>:<chain_name> with ticker <token_ticker>, flags <Flag 1>,<Flag2>...<Flag N>\n"
            "\t   and custom parameters list <Param 1>, <Param 2>...<Param N>.\n"
            "\nExtended CF20 token declaration\n"
            "token_decl -net <net_name> -chain <chain_name> -token <token_ticker> -type CF20 "
                "-total_supply <total supply/if 0 = endless> -decimals <18> -signs_total <sign total> -signs_emission <signs for emission> -certs <certs list>\n"
            "\t -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...\n"
            "\t [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
            "\t   Declare new token for <netname>:<chain_name> with ticker <token_ticker>, flags <Flag 1>,<Flag2>...<Flag N>\n"
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
            "\t -description <value>:\t Set description for this token\n"
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

    dap_cli_server_cmd_add("token_update_sign", com_token_decl_sign, "Token update add sign and new sign",
                                        "token_update_sign -net <net_name> -chain <chain_name> -datum <datum_hash> -certs <certs list> -new_certs <certs list>\n"
                                        "\t Sign existent <datum hash> in mempool with <certs list>\n"
    );
    // Token commands

    dap_cli_server_cmd_add ("token_decl_sign", com_token_decl_sign, "Token declaration add sign",
            "token_decl_sign -net <net_name> -chain <chain_name> -datum <datum_hash> -certs <certs list>\n"
            "\t Sign existent <datum hash> in mempool with <certs list>\n"
            );

    dap_cli_server_cmd_add ("token_emit", com_token_emit, "Token emission",
                            "token_emit { sign | -token <mempool_token_ticker> -emission_value <value>"
                            "-addr <addr> [-chain_emission <chain_name>] -net <net_name> -certs <cert list>\n");

    dap_cli_server_cmd_add ("mempool_list", com_mempool_list,
                                        "List mempool (entries or transaction) for (selected chain network or wallet)",
            "mempool_list -net <net_name> [-chain <chain_name>] [-addr <addr>] [-fast] \n");

    dap_cli_server_cmd_add ("mempool_check", com_mempool_check, "Check mempool entrie for presence in selected chain network",
            "mempool_check -net <net_name> -datum <datum hash>\n");

    dap_cli_server_cmd_add ("mempool_proc", com_mempool_proc, "Proc mempool entrie with specified hash for selected chain network",
            "mempool_proc -net <net_name> -datum <datum hash> -chain <chain name>\n"
            "CAUTION!!! This command will process transaction with any comission! Parameter minimum_comission will not be taken into account!");

    dap_cli_server_cmd_add ("mempool_proc_all", com_mempool_proc_all, "Proc mempool all entries for selected chain network",
                            "mempool_proc_all -net <net_name> -chain <chain_name>\n");

    dap_cli_server_cmd_add ("mempool_delete", com_mempool_delete, "Delete datum with hash <datum hash> for selected chain network",
            "mempool_delete -net <net_name> -datum <datum hash>\n");

    dap_cli_server_cmd_add ("mempool_add_ca", com_mempool_add_ca,
                                        "Add pubic certificate into the mempool to prepare its way to chains",
            "mempool_add_ca -net <net_name> [-chain <chain_name>] -ca_name <priv_cert_name>\n");

    dap_cli_server_cmd_add ("chain_ca_pub", com_chain_ca_pub,
                                        "Add pubic certificate into the mempool to prepare its way to chains",
            "chain_ca_pub -net <net_name> [-chain <chain_name>] -ca_name <priv_cert_name>\n");

    dap_cli_server_cmd_add ("chain_ca_copy", com_chain_ca_copy,
                                        "Copy pubic certificate into the mempool to prepare its way to chains",
            "chain_ca_copy -net <net_name> [-chain <chain_name>] -ca_name <pub_cert_name>\n");

    // Transaction commands
    dap_cli_server_cmd_add ("tx_create", com_tx_create, "Make transaction",
            "tx_create -net <net_name> -chain <chain_name> -value <value> -token <token_ticker> -to_addr <addr>"
            "{-from_wallet <wallet_name> | -from_emission <emission_hash> {-cert <cert_name> | -wallet_fee <wallet_name>}} -fee <value>\n");
    dap_cli_server_cmd_add ("tx_create_json", com_tx_create_json, "Make transaction",
                "tx_create_json -net <net_name> -chain <chain_name> -json <json_file_path>\n" );
    dap_cli_server_cmd_add ("tx_cond_create", com_tx_cond_create, "Make cond transaction",
                                        "tx_cond_create -net <net_name> -token <token_ticker> -w <wallet_name>"
                                        " -cert <pub_cert_name> -value <value_datoshi> -fee <value> -unit {mb | kb | b | sec | day} -srv_uid <numeric_uid>\n" );

    dap_cli_server_cmd_add ("tx_verify", com_tx_verify, "Verifing transaction in mempool",
            "tx_verify -net <net_name> -chain <chain_name> -tx <tx_hash>\n" );

    // Transaction history
    dap_cli_server_cmd_add("tx_history", com_tx_history, "Transaction history (for address or by hash)",
            "tx_history  {-addr <addr> | -w <wallet_name> | -tx <tx_hash>} [-net <net_name>] [-chain <chain_name>]\n"
            "tx_history -all -net <net_name> [-chain <chain_name>]\n");

	// Ledger info
    dap_cli_server_cmd_add("ledger", com_ledger, "Ledger information",
            "ledger list coins -net <net_name>\n"
            "ledger list threshold [-hash <tx_treshold_hash>] -net <net_name>\n"
            "ledger list balance -net <net_name>\n"
            "ledger info -hash <tx_hash> -net <net_name> [-unspent]\n"
            "ledger tx -all -net <net_name> [-unspent]\n"
            "ledger tx {-addr <addr> | -w <wallet_name> | -tx <tx_hash>} -net <net_name>\n");

    // Token info
    dap_cli_server_cmd_add("token", com_token, "Token info",
            "token list -net <net_name>\n"
            "token info -net <net_name> -name <token_ticker>\n");

    // Log
    dap_cli_server_cmd_add ("print_log", com_print_log, "Print log info",
                "print_log [ts_after <timestamp>] [limit <line_numbers>]\n" );

    // Statisticss
    dap_cli_server_cmd_add("stats", com_stats, "Print statistics",
                "stats cpu");

    // Export GDB to JSON
    dap_cli_server_cmd_add("gdb_export", cmd_gdb_export, "Export gdb to JSON",
                                        "gdb_export filename <filename without extension> [-groups <group names list>]");

    //Import GDB from JSON
    dap_cli_server_cmd_add("gdb_import", cmd_gdb_import, "Import gdb from JSON",
                                        "gdb_import filename <filename without extension>");

    dap_cli_server_cmd_add ("remove", cmd_remove, "Delete chain files or global database",
           "remove -gdb\n"
           "remove -chains [-net <net_name> | -all]\n"
                     "Be careful, the '-all' option for '-chains' will delete all chains and won't ask you for permission!");

    // Decree create command
    dap_cli_server_cmd_add ("decree", cmd_decree, "Work with decree",
            "decree create common -net <net_name> [-chain <chain_name>] -decree_chain <chain_name> -certs <certs list> -<Subtype param name> <Subtype param Value>\n"
            "decree create service -net <net_name> [-chain <chain_name>] -decree_chain <chain_name> -srv_id <service_id> -certs <certs list> -<Subtype param name> <Subtype param Value>\n"
            "decree sign -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <certs_list>\n"
            "decree anchor -net <net_name> -chain <chain_name> -datum <datum_hash> -certs <certs_list>\n"
            "decree find -net <net_name> -hash <decree_hash>. Find decree by hash and show it's status (apllied or not)\n"
            "\t==Subtype Params==\n"
            "\t\t -fee <value>: sets fee for tx in net\n"
            "\t\t -to_addr <wallet_addr>: sets wallet addr for network fee\n"
            "\t\t -new_certs <certs_list>: sets new owners set for net\n"
            "\t\t -signs_verify <value>: sets minimum number of owners needed to sign decree\n"
            "decree info -net <net_name>. Displays information about the parameters of the decrees in the network.\n");

    // Exit - always last!
    dap_cli_server_cmd_add ("exit", com_exit, "Stop application and exit",
                "exit\n" );
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
