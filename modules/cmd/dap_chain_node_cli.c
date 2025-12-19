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

#include <errno.h>
#include <assert.h>
//#include <glib.h>
#include <pthread.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_list.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_node_sync_client.h"
#include "dap_chain_node_cli_cmd_tx.h"
#include "dap_cli_server.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_rpc.h"
#include "dap_notify_srv.h"
#include "dap_json_rpc_response.h"

#define LOG_TAG "chain_node_cli"
static bool s_debug_cli = false;
/*commands for parsing json response*/
static int s_print_for_mempool_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt);
static int s_print_for_token_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt);
static int s_print_for_tx_history_all(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt);
static int s_print_for_global_db(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt);
static int s_print_for_ledger_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt);


/**
 * @brief dap_chain_node_cli_init
 * Initialization of the server side of the interaction
 * with the console kelvin-node-cli
 * init commands description
 * return 0 if OK, -1 error
 * @param g_config
 * @param a_server_enabled - if server and rpc enabled will be wrn inform
 * @return int
 */
int dap_chain_node_cli_init(dap_config_t * g_config)
{
    if ( !dap_config_get_item_bool_default(g_config, "cli-server", "enabled", true) )
        return log_it( L_WARNING, "CLI server is disabled" ), 0;
    s_debug_cli = dap_config_get_item_bool_default(g_config, "cli-server", "debug-cli", false);
    if ( dap_cli_server_init(s_debug_cli, "cli-server") )
        return log_it(L_ERROR, "Can't init CLI server!"), -1;
    if (dap_config_get_item_bool_default(g_config, "rpc", "enabled", false)) {
        dap_chain_node_rpc_init(g_config);
    }

    dap_cli_server_cmd_add("global_db", com_global_db, s_print_for_global_db, "Work with global database", dap_chain_node_cli_cmd_id_from_str("global_db"),
            "global_db flush \n"
                "\tFlushes the current state of the database to disk.\n\n"
            "global_db write -group <group_name> -key <key_name> -value <value>\n"
                "\tWrites a key value to a specified group in the database.\n\n"
            "global_db read -group <group_name> -key <key_name>\n"
                "\tReads a value by key from a specified group.\n\n"
            "global_db delete -group <group_name> -key <key_name>\n"
                "\tRemoves a value by key from a specified group. Change record to hole type.\n\n"
            "global_db group_list [-mask <mask>] [-all] [-h]\n"
                "\tGets a list of groups in the database.\n"
                "\t-mask <mask>: list groups by mask\n"
                "\t-all: count actual and holes records types\n\n"
            "global_db drop_table -group <group_name>\n"
                "\tPerforms deletion of the entire group in the database.\n\n"
            "global_db get_keys -group <group_name>\n"
                "\tGets all record keys from a specified group.\n\n"
            "global_db clear -group <group_name> | -mask <mask> | -all [-pinned]\n"
                "\tRemove all hole type records from a specified group or all groups by mask.\n"
                "\t-mask <mask>: clear groups by mask\n"
                "\t-all: clear all groups\n"
                "\t-pinned: remove pinned records too\n\n"
            "global_db clusters [-verbose] [-h]\n"
                "\tDisplays list of all global_db clusters.\n"
                "\t-verbose: show links information and role_cluster members for each cluster\n"
                "\t-h: display in table format\n\n"

//                    "global_db wallet_info set -addr <wallet address> -cell <cell id> \n\n"
            );
    dap_cli_server_cmd_add("mempool", com_signer, NULL, "Sign operations", dap_chain_node_cli_cmd_id_from_str("mempool"),
               "mempool sign -cert <priv_cert_name> -net <net_name> -chain <chain_name> -file <filename> [-mime {<SIGNER_FILENAME,SIGNER_FILENAME_SHORT,SIGNER_FILESIZE,SIGNER_DATE,SIGNER_MIME_MAGIC> | <SIGNER_ALL_FLAGS>}]\n"
               "mempool check -cert <priv_cert_name> -net <net_name> {-file <filename> | -hash <hash>} [-mime {<SIGNER_FILENAME,SIGNER_FILENAME_SHORT,SIGNER_FILESIZE,SIGNER_DATE,SIGNER_MIME_MAGIC> | <SIGNER_ALL_FLAGS>}]\n"
                                          );
    dap_cli_server_cmd_add("node", com_node, NULL, "Work with node", dap_chain_node_cli_cmd_id_from_str("node"),
                    "node add { -net <net_name> | -rpc [-port <port>] } | { -rpc -addr <node_address> -host <node_host> [-port <port>] }\n\n"
                    "node del -net <net_name> {-addr <node_address> | -alias <node_alias>}\n\n"
                    "node link {add | del}  -net <net_name> {-addr <node_address> | -alias <node_alias>} -link <node_address>\n\n"
                    "node alias -addr <node_address> -alias <node_alias>\n\n"
                    "node connect -net <net_name> {-addr <node_address> | -alias <node_alias> | auto}\n\n"
                    "node handshake -net <net_name> {-addr <node_address> | -alias <node_alias>}\n"
                    "node connections [-net <net_name>]\n"
                    "node balancer -net <net_name>\n"
                    "node dump { [-net <net_name> | -addr <node_address>] } | { -rpc [-addr <node_address>] }\n\n"
                    "node list { -net <net_name> [-addr <node_address> | -alias <node_alias>] [-full] } | -rpc\n\n"
                    "node ban -net <net_name> -certs <certs_name> [-addr <node_address> | -host <ip_v4_or_v6_address>]\n"
                    "node unban -net <net_name> -certs <certs_name> [-addr <node_address> | -host <ip_v4_or_v6_address>]\n"
                    "node banlist\n\n");
    
    dap_cli_server_cmd_add ("version", com_version, NULL, "Return software version", dap_chain_node_cli_cmd_id_from_str("version"),
                                        "version\n"
                                        "\tReturn version number\n"
                                        );

    dap_cli_server_cmd_add ("help", com_help, NULL, "Description of command parameters", dap_chain_node_cli_cmd_id_from_str("help"),
                                        "help [<command>]\n"
                                        "\tObtain help for <command> or get the total list of the commands\n"
                                        );
    dap_cli_server_cmd_add ("?", com_help, NULL, "Synonym for \"help\"", dap_chain_node_cli_cmd_id_from_str("help"),
                                        "? [<command>]\n"
                                        "\tObtain help for <command> or get the total list of the commands\n"
                                        );
    // Token commands
    dap_cli_server_cmd_add ("token_decl", com_token_decl, NULL, "Token declaration", dap_chain_node_cli_cmd_id_from_str("token_decl"),
            "Simple token declaration:\n"
            "token_decl -net <net_name> [-chain <chain_name>] -token <token_ticker> -total_supply <total_supply> -signs_total <sign_total> -signs_emission <signs_for_emission> -certs <certs_list>\n"
            "\t  Declare new simple token for <net_name>:<chain_name> with ticker <token_ticker>, maximum emission <total_supply> and <signs_for_emission> from <signs_total> signatures on valid emission\n"
            "\nExtended private token declaration\n"
            "token_decl -net <net_name> [-chain <chain_name>] -token <token_ticker> -type private -total_supply <total_supply> "
                "-decimals <18> -signs_total <sign_total> -signs_emission <signs_for_emission> -certs <certs_list> -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...\n"
            "\t [-<Param_name_1> <Param_Value_1>] [-Param_name_2> <Param_Value_2>] ...[-<Param_Name_N> <Param_Value_N>]\n"
            "\t   Declare new token for <net_name>:<chain_name> with ticker <token_ticker>, flags <Flag_1>,<Flag_2>...<Flag_N>\n"
            "\t   and custom parameters list <Param_1>, <Param_2>...<Param_N>.\n"
            "\nExtended CF20 token declaration\n"
            "token_decl -net <net_name> [-chain <chain_name>] -token <token_ticker> -type CF20 "
                "-total_supply <total_supply/if_0 =_endless> -decimals <18> -signs_total <sign_total> -signs_emission <signs_for_emission> -certs <certs_list>\n"
            "\t -flags [<Flag_1>][,<Flag_2>]...[,<Flag_N>]...\n"
            "\t [-<Param_name_1> <Param_Value_1>] [-Param_name_2> <Param_Value_2>] ...[-<Param_Name_N> <Param_Value_N>]\n"
            "\t   Declare new token for <net_name>:<chain_name> with ticker <token_ticker>, flags <Flag_1>,<Flag_2>...<Flag_N>\n"
            "\t   and custom parameters list <Param_1>, <Param_2>...<Param_N>.\n"
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
            "\n\n"
            
            "Hint:\n"
            "\texample coins amount syntax (only natural) 1.0 123.4567\n"
            "\texample datoshi amount syntax (only integer) 1 20 0.4321e+4\n\n"
    );
    dap_cli_server_cmd_add ("token_decl_sign", com_token_decl_sign, NULL, "Token declaration add sign", dap_chain_node_cli_cmd_id_from_str("token_decl_sign"),
            "token_decl_sign -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <certs_list>\n"
            "\t Sign existent <datum_hash> in mempool with <certs_list>\n"
    );

    dap_cli_server_cmd_add ("token_update", com_token_update, NULL, "Token update", dap_chain_node_cli_cmd_id_from_str("token_update"),
                            "\nPrivate or CF20 token update\n"
                            "token_update -net <net_name> [-chain <chain_name>] -token <existing_token_ticker> -type <CF20|private> [-total_supply_change <value>] "
                            "-certs <name_certs> [-flag_set <flag>] [-flag_unset <flag>] [-total_signs_valid <value>] [-description <value>] "
                            "[-tx_receiver_allowed <value>] [-tx_receiver_blocked <value>] [-tx_sender_allowed <value>] [-tx_sender_blocked <value>] "
                            "[-add_cert <name_certs>] [-remove_certs <pkeys_hash>]\n"
                            "==Flags==\n"
                            "\tALL_BLOCKED: \t\t\t\tBlocks all permissions.\n"
                            "\tALL_ALLOWED: \t\t\t\tAllows all permissions unless they are blocked. Be careful with this mode.\n"
                            "\tALL_FROZEN: \t\t\t\tTemporarily freezes all permissions\n"
                            "\tALL_UNFROZEN: \t\t\t\tUnfreezes all frozen permissions\n"
                            "\tSTATIC_ALL: \t\t\t\tBlocks manipulations with a token after declaration. Tokens are declared statically.\n"
                            "\tSTATIC_FLAGS: \t\t\t\tBlocks manipulations with token flags after declaration.\n"
                            "\tSTATIC_PERMISSIONS_ALL: \t\tBlocks all manipulations with permissions list after declaration.\n"
                            "\tSTATIC_PERMISSIONS_DATUM_TYPE: \t\tBlocks all manipulations with datum permissions list after declaration.\n"
                            "\tSTATIC_PERMISSIONS_TX_SENDER: \t\tBlocks all manipulations with transaction senders permissions list after declaration.\n"
                            "\tSTATIC_PERMISSIONS_TX_RECEIVER: \tBlocks all manipulations with transaction receivers permissions list after declaration.\n"
                            "\n"
                            "==Params==\n"
                            "General:\n"
                            "\t -total_supply_change <value>:\t\t Sets the maximum amount of token supply. Specify 'INF' to set unlimited total supply.\n"
                            "\t -certs <name_certs>:\t\t\t Here use the very certificates which were used to sign the token being updated.\n"
                            "Additional:\n"
                            "\t -description <token_description>:\t Shows updated description for this token.\n"
                            "Installing and removing the flag:\n"
                            "\t -flag_set <flag_name>:\t\t\t Adds specified flag to the list of active flags.\n"
                            "\t -flag_unset <flag_name>:\t\t Removes specified flag from the list of active flags.\n"
                            "Work with the number of signatures required for the issue:\n"
                            "\t -total_signs_valid <value>:\t\t Sets the minimum amount of valid signatures.\n"
                            "\t -add_certs <cert_list>:\t\t Adds certificates to the certificates list of the token.\n"
                            "\t -remove_certs <pkeys_hash>:\t\t Removes certificates from the certificates list using theirs public key hashes.\n"
                            "Tx receiver addresses allowed/blocked:\n"
                            "\t -tx_receiver_allowed <wallet_addr>:\t Adds specified wallet address to the list of allowed receivers.\n"
                            "\t -tx_receiver_blocked <wallet_addr>:\t Adds specified wallet address to the list of blocked receivers.\n"
                            "\nTx sender addresses allowed/blocked:\n"
                            "\t -tx_sender_allowed <wallet_addr>:\t Adds specified wallet address to the list of allowed senders.\n"
                            "\t -tx_sender_blocked <wallet_addr>:\t Adds specified wallet address to the list of blocked senders.\n"
                            "\n"
    );
    dap_cli_server_cmd_add("token_update_sign", com_token_decl_sign, NULL, "Token update add sign to datum", dap_chain_node_cli_cmd_id_from_str("token_update_sign"),
                                        "token_update_sign -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <cert_list>\n"
                                        "\t Sign existent <datum hash> in mempool with <certs_list>\n"
    );

    dap_cli_server_cmd_add ("token_emit", com_token_emit, NULL, "Token emission", dap_chain_node_cli_cmd_id_from_str("token_emit"),
                            "token_emit { sign -emission <hash> | -token <mempool_token_ticker> -emission_value <value> -addr <addr> } "
                            "[-chain_emission <chain_name>] -net <net_name> -certs <cert_list>\n"
                            "Available hint:\n"
                            "\texample coins amount syntax (only natural) 1.0 123.4567\n"
                            "\texample datoshi amount syntax (only integer) 1 20 0.4321e+4\n\n");

    dap_cli_server_cmd_add ("wallet", com_tx_wallet, NULL, "Wallet operations", dap_chain_node_cli_cmd_id_from_str("wallet"),
                            "wallet list\n"
                            "wallet new -w <wallet_name> [-sign <sign_type>] [-restore <hex_value> | -restore_legacy <restore_string>] [-net <net_name>] [-force] [-password <password>]\n"
                            "wallet info {-addr <addr> | -w <wallet_name>} -net <net_name>\n"
                            "wallet activate -w <wallet_name> -password <password> [-ttl <password_ttl_in_minutes>]\n"
                            "wallet deactivate -w <wallet_name>>\n"
                            "wallet outputs {-addr <addr> | -w <wallet_name>} -net <net_name> -token <token_tiker> [{-cond [-type <cond_type>] | -value <uint256_value>}] [-mempool_check]\n"
                                "\t Available conditional output types for -type parameter:\n"
                                "\t   srv_pay, srv_xchange, srv_stake_pos_delegate, srv_stake_lock, fee\n"
                            "wallet convert -w <wallet_name> {-password <password> | -remove_password }\n"
                            "wallet find -addr <addr> {-file <file path>}\n"
                            "wallet shared hold - creates new shared funds transaction\n"
                                "\t-net <net_name>\n"
                                "\t-w <wallet_name> - wallet for take funds, pay fee and sign tx\n"
                                "\t-token <ticker> - token ticker to hold\n"
                                "\t-value <value> - funds value to hold\n"
                                "\t-fee <value> - fee value\n"
                                "\t-signs_minimum <value_int> - number of required valid signatures for funds debit tx\n"
                                "\t-pkey_hashes <hash1[,hash2,...,hashN]> - owners public key hashes, who can sign a debit tx\n"
                                "\t[-tag \"<str>\"] - additional info about tx\n"
                                "\t[-H {hex(default) | base58}] - tx hash return format\n"
                            "wallet shared refill - refills value on shared funds transaction\n"
                                "\t-net <net_name>\n"
                                "\t-w <wallet_name> - wallet for take funds and pay fee\n"
                                "\t-value <value> - funds value to refill\n"
                                "\t-fee <value> - fee value\n"
                                "\t-tx <transaction_hash> - hash of the shared funds tx to refill\n"
                                "\t[-H {hex(default) | base58}] - tx hash return format\n"
                            "wallet shared take - creates debit tx to take value from shared funds tx\n"
                                "\t-net <net_name>\n"
                                "\t-w <wallet_name> - wallet to pay fee\n"
                                "\t-tx <transaction_hash> - hash of the shared funds tx to take\n"
                                "\t-to_addr <addr1[,addr2,...,addrN]> - recipient addresses, their quantity must match the values specified number\n"
                                "\t-value <value1[,value2,...,valueN]> - value sent to each recipient, must match the addresses number\n"
                                "\t-fee <value> - fee value\n"
                                "\t[-H {hex(default) | base58}] - tx hash return format\n"
                            "wallet shared sign - add wallet signature to  debit tx\n"
                                "\t-net <net_name>\n"
                                "\t-w <wallet_name> | -cert <cert_name> - wallet or cert to sign\n"
                                "\t-tx <transaction_hash> - shared funds tx hash to sign\n"
                                "\t[-H {hex(default) | base58}] - tx hash return format\n"
                            "wallet shared info - get info about shared funds tx by hash\n"
                                "\t-net <net_name>\n"
                                "\t-tx <transaction_hash> - shared funds tx hash to get info\n"
                                "\t[-H {hex(default) | base58}] - tx hash format\n"
                            "wallet shared list - list wallet shared transactions from GDB\n"
                                "\t[-net <net_name>] - filter by net name\n"
                                "\t[-pkey <pkey_hash>] - filter by public key hash\n"
                                "\t[-addr <address>] - filter by wallet address\n"
                                "\t[-w <wallet_name>] - filter by wallet name\n"
                                "\t[-cert <cert_name>] - filter by certificate name\n"
                                "\t  Note: -pkey, -addr, -w, and -cert are mutually exclusive\n"
                                "\t[-local] - filter by local wallets and certificates\n"
                                "\t[-H {hex(default) | base58}] - hash format for output\n"
                            "Hint:\n"
                                "\texample value_coins (only natural) 1.0 123.4567\n"
                                "\texample value_datoshi (only integer) 1 20 0.4321e+4\n"
    );

    dap_cli_cmd_t *l_cmd_mempool = dap_cli_server_cmd_add("mempool", com_mempool, s_print_for_mempool_list, "Command for working with mempool", dap_chain_node_cli_cmd_id_from_str("mempool"),
                           "mempool list -net <net_name> [-chain <chain_name>] [-addr <addr>] [-brief] [-limit] [-offset] [-h]\n"
                           "\tList mempool (entries or transaction) for (selected chain network or wallet)\n"
                           "mempool check -net <net_name> [-chain <chain_name>] -datum <datum_hash>\n"
                           "\tCheck mempool entrie for presence in selected chain network\n"
                           "mempool proc -net <net_name> [-chain <chain_name>] -datum <datum_hash>\n"
                           "\tProc mempool entrie with specified hash for selected chain network\n"
                           "\tCAUTION!!! This command will process transaction with any comission! Parameter minimum_comission will not be taken into account!\n"
                           "mempool proc_all -net <net_name> -chain <chain_name>\n"
                           "\tProc mempool all entries for selected chain network\n"
                           "mempool delete -net <net_name> [-chain <chain_name>] -datum <datum_hash>\n"
                           "\tDelete datum with hash <datum hash> for selected chain network\n"
                           "mempool dump -net <net_name> [-chain <chain_name>] -datum <datum_hash>\n"
                           "\tOutput information about datum in mempool\n"
                           "mempool add_ca -net <net_name> [-chain <chain_name>] -ca_name <pub_cert_name>\n"
                           "\tAdd pubic certificate into the mempool to prepare its way to chains\n"
                           "mempool count -net <net_name> [-chain <chain_name>]\n"
                           "\tDisplays the number of elements in the mempool of a given network.");

    dap_cli_server_alias_add(l_cmd_mempool, "list", "mempool_list");
    dap_cli_server_alias_add(l_cmd_mempool, "check", "mempool_check");
    dap_cli_server_alias_add(l_cmd_mempool, "proc", "mempool_proc");
    dap_cli_server_alias_add(l_cmd_mempool, "proc_all", "mempool_proc_all");
    dap_cli_server_alias_add(l_cmd_mempool, "delete", "mempool_delete");
    dap_cli_server_alias_add(l_cmd_mempool, "add_ca", "mempool_add_ca");
    dap_cli_server_alias_add(l_cmd_mempool, "add_ca", "chain_ca_copy");

    dap_cli_server_cmd_add ("chain_ca_pub", com_chain_ca_pub, NULL,
                                        "Add pubic certificate into the mempool to prepare its way to chains", dap_chain_node_cli_cmd_id_from_str("chain_ca_pub"),
            "chain_ca_pub -net <net_name> [-chain <chain_name>] -ca_name <priv_cert_name>\n");

    // Transaction commands
    dap_cli_server_cmd_add ("tx_create", com_tx_create, NULL, "Make transaction", dap_chain_node_cli_cmd_id_from_str("tx_create"),
                "tx_create -net <net_name> [-chain <chain_name>] -value <value> -token <token_ticker> -to_addr <addr> [-lock_before <unlock_time_in_RCF822 or YYMMDD>"
                "{-from_wallet <wallet_name> | -from_emission <emission_hash> {-cert <cert_name> | -wallet_fee <wallet_name>}} -fee <value>\n\n"
                "Hint:\n"
                "\texample coins amount syntax (only natural) 1.0 123.4567\n"
                "\texample datoshi amount syntax (only integer) 1 20 0.4321e+4\n\n");
    dap_cli_server_cmd_add ("tx_create_json", com_tx_create_json, NULL, "Make transaction", dap_chain_node_cli_cmd_id_from_str("tx_create_json"),
                "tx_create_json -net <net_name> [-chain <chain_name>] -json <json_file_path>\n" );
    dap_cli_server_cmd_add ("mempool_add", com_mempool_add, NULL, "Make transaction and put that to mempool", dap_chain_node_cli_cmd_id_from_str("mempool_add"),
                "json_datum_mempool_put  -net <net_name> [-chain <chain_name>] -json <json_file_path> | -tx_obj <tx_json_object>\n" );
    dap_cli_server_cmd_add ("tx_cond_create", com_tx_cond_create, NULL, "Make cond transaction", dap_chain_node_cli_cmd_id_from_str("tx_cond_create"),
                "tx_cond_create -net <net_name> -token <token_ticker> -w <wallet_name>"
                " { -cert <pub_cert_name> | -pkey <pkey_hash> } -value <value> -fee <value> -unit {B | SEC} -srv_uid <numeric_uid>\n\n" 
                "Hint:\n"
                "\texample coins amount syntax (only natural) 1.0 123.4567\n"
                "\texample datoshi amount syntax (only integer) 1 20 0.4321e+4\n\n");
    dap_cli_server_cmd_add ("tx_cond_remove", com_tx_cond_remove, NULL, "Remove cond transactions and return funds from condition outputs to wallet",  dap_chain_node_cli_cmd_id_from_str("tx_cond_remove"),
                "tx_cond_remove -net <net_name> -hashes <hash1,hash2...> -w <wallet_name>"
                " -fee <value> -srv_uid <numeric_uid>\n" 
                "Hint:\n"
                "\texample coins amount syntax (only natural) 1.0 123.4567\n"
                "\texample datoshi amount syntax (only integer) 1 20 0.4321e+4\n\n");
    dap_cli_server_cmd_add ("tx_cond_unspent_find", com_tx_cond_unspent_find, NULL, "Find cond transactions by wallet", dap_chain_node_cli_cmd_id_from_str("tx_cond_unspent_find"),
                                        "tx_cond_unspent_find -net <net_name> -srv_uid <numeric_uid> -w <wallet_name> \n" );

    dap_cli_server_cmd_add ("tx_verify", com_tx_verify, NULL, "Verifing transaction in mempool", dap_chain_node_cli_cmd_id_from_str("tx_verify"),
            "tx_verify -net <net_name> [-chain <chain_name>] -tx <tx_hash>\n" );

    // Transaction history
    dap_cli_server_cmd_add("tx_history", com_tx_history, s_print_for_tx_history_all, "Transaction history (for address or by hash)", dap_chain_node_cli_cmd_id_from_str("tx_history"),
            "tx_history  {-addr <addr> | {-w <wallet_name> } -net <net_name>} [-chain <chain_name>] [-limit] [-offset] [-head] [-h]\n"
            "tx_history -all -net <net_name> [-chain <chain_name>] [-limit] [-offset] [-head] [-h]\n"
            "tx_history -tx <tx_hash> -net <net_name> [-chain <chain_name>] \n"
            "tx_history -count -net <net_name>\n");

	// Ledger info
    dap_cli_server_cmd_add("ledger", com_ledger, s_print_for_ledger_list, "Ledger information", dap_chain_node_cli_cmd_id_from_str("ledger"),
            "ledger list coins -net <net_name> [-limit] [-offset] [-h]\n"
            "ledger list threshold [-hash <tx_treshold_hash>] -net <net_name> [-limit] [-offset] [-head] [-h]\n"
            "ledger list balance -net <net_name> [-limit] [-offset] [-head] [-h]\n"
            "ledger info -hash <tx_hash> -net <net_name> [-unspent]\n"
            "ledger trace -net <net_name> -from <hash1> -to <hash2> [-H {hex|base58}]\n"
            "\t Build transaction chain from hash2 to hash1 using backward traversal\n"
            "ledger event list -net <net_name> [-group <group_name>]\n"
            "ledger event dump -net <net_name> -hash <tx_hash>\n"
            "ledger event create -net <net_name> [-chain <chain_name>] -w <wallet_name> -service_key <cert_name> -srv_uid <service_uid> "
            "-group <group_name> -event_type <event_type> [-event_data <event_data>] [-fee <fee_value>] [-H <hex|base58>]\n"
            "ledger event key add -net <net_name> -hash <pkey_hash> -certs <certs_list>\n"
            "ledger event key remove -net <net_name> -hash <pkey_hash> -certs <certs_list>\n"
            "ledger event key list -net <net_name> [-H <hex|base58>]\n");

    // Token info
    dap_cli_server_cmd_add("token", com_token, s_print_for_token_list, "Token info", dap_chain_node_cli_cmd_id_from_str("token"),
            "token list -net <net_name>\n"
            "token info -net <net_name> -name <token_ticker>\n");

    // Statisticss
    dap_cli_server_cmd_add("stats", com_stats, NULL, "Print statistics", dap_chain_node_cli_cmd_id_from_str("stats"),
                "stats cpu");

    // Export GDB to JSON
    dap_cli_server_cmd_add("gdb_export", cmd_gdb_export, NULL, "Export gdb to JSON", dap_chain_node_cli_cmd_id_from_str("gdb_export"),
                                        "gdb_export filename <filename without extension> [-groups <group names list>]");

    //Import GDB from JSON
    dap_cli_server_cmd_add("gdb_import", cmd_gdb_import, NULL, "Import gdb from JSON", dap_chain_node_cli_cmd_id_from_str("gdb_import"),
                                        "gdb_import filename <filename_without_extension>");

    dap_cli_server_cmd_add ("remove", cmd_remove, NULL, "Delete chain files or global database", dap_chain_node_cli_cmd_id_from_str("remove"),
           "remove -gdb\n"
           "remove -chains [-net <net_name> | -all]\n"
                     "Be careful, the '-all' option for '-chains' will delete all chains and won't ask you for permission!");

    // Decree create command
    dap_cli_server_cmd_add ("decree", cmd_decree, NULL, "Work with decree", dap_chain_node_cli_cmd_id_from_str("decree"),
            "decree create [common] -net <net_name> [-chain <chain_name>] -decree_chain <chain_name> -certs <certs_list> {-fee <net_fee_value> -to_addr <net_fee_wallet_addr> |"
                                                                                                                        " -hardfork_from <atom_number> [-trusted_addrs <node_addr1,node_addr2,...>] [-addr_pairs <\"old_addr:new_addr\",\"old_addr1:new_addr1\"...>] |"
                                                                                                                        " -hardfork_retry |"
                                                                                                                        " -hardfork_complete |"
                                                                                                                        " -hardfork_cancel |"
                                                                                                                        " -new_certs <new_owners_certs_list> |"
                                                                                                                        " -signs_verify <value>}\n"
            "Creates common network decree in net <net_name>. Decree adds to chain -chain and applies to chain -decree_chain. If -chain and -decree_chain is different you must create anchor in -decree_chain that is connected to this decree."
            "\nCommon decree parameters:\n"
            "\t -fee <value>: sets network fee\n"
            "\t -to_addr <wallet_addr>: sets wallet addr for network fee\n"
            "\t -hardfork_from <atom_number>: start hardfork routine from specified block number\n"
            "\t -trusted_addrs <node_addr1,node_addr2,...>: addresses of nodes who can provide service state datums for hardfork routine\n"
            "\t -addr_pairs <\"old_addr:new_addr\",\"old_addr1:new_addr1\"...>: blockchain addresses of wallets pairs moving balances from old_addr to new_addr with hardfork routine\n"
            "\t -hardfork_retry: try to retry unsucsessful hardfork routine immediately\n"
            "\t -hardfork_complete: finilize hardfork routine immediately\n"
            "\t -hardfork_cancel: cancel active (WARNING: not engaged, active only) hardfork routine if any, and ban current chain generation in network\n"
            "\t -new_certs <certs_list>: sets new owners set for net\n"
            "\t -signs_verify <value>: sets minimum number of owners needed to sign decree\n\n"
            "decree sign -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <certs_list>\n"
            "Signs decree with hash -datum.\n\n"
            "decree anchor -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <certs_list>\n"
            "Creates anchor for decree with hash -datum.\n\n"
            "decree find -net <net_name> -hash <decree_hash>\n"
            "Find decree by hash and show it's status (apllied or not)\n\n"
            "decree info -net <net_name>\n"
            "Displays information about the parameters of the decrees in the network.\n\n"
            "Hint:\n"
            "\texample coins amount syntax (only natural) 1.0 123.4567\n"
            "\texample datoshi amount syntax (only integer) 1 20 0.4321e+4\n\n");

    dap_cli_server_cmd_add ("exec_cmd", com_exec_cmd, NULL, "Execute command on remote node", dap_chain_node_cli_cmd_id_from_str("exec_cmd"),
            "exec_cmd -net <net_name> -addr <node_addr> -cmd <command,and,all,args,separated,by,commas>\n" );

    //Find command
    dap_cli_server_cmd_add("find", cmd_find, NULL, "The command searches for the specified elements by the specified attributes", dap_chain_node_cli_cmd_id_from_str("find"),
                           "find datum -net <net_name> [-chain <chain_name>] -hash <datum_hash>\n"
                           "\tSearches for datum by hash in the specified network in chains and mempool.\n"
                           "find atom -net <net_name> [-chain <chain_name>] -hash <atom_hash>\n"
                           "\tSearches for an atom by hash in a specified network in chains.\n"
                           "find decree -net <net_name> [-chain <chain_name>] -type <type_decree> [-where <chains|mempool>]\n"
                           "\tSearches for decrees by hash in the specified decree type in the specified network in its chains.\n"
                           "\tTypes decree: fee, owners, owners_min, stake_approve, stake_invalidate, min_value, "
                           "min_validators_count, ban, unban, reward, validator_max_weight, emergency_validators, check_signs_structure\n");


    dap_cli_server_cmd_add ("file", com_file, NULL, "Work with logs and files", dap_chain_node_cli_cmd_id_from_str("file"),
                "file print {-num_line <number_of_lines> | -ts_after <Tue, 10 Dec 2024 18:37:47 +0700> } {-log | -path <path_to_file>}\n"
                "\t print the last <num_line> lines from the log file or all logs after the specified date and time\n"
                "\t -path <path_to_file> allows printing from a text file, but -ts_after option might not work\n"
                "file export {-num_line <number_of_lines> | -ts_after <m/d/Y-H:M:S>} {-log | -path <path_to_file>} -dest <destination_path>\n"
                "\t export last <num_line> lines from the log file or all logs after the specified date and time\n"
                "\t -path <path_to_file> allows exporting from a text file, but -ts_after option might not work\n"
                "file clear_log\n"
                "\t CAUTION !!! This command will clear the entire log file\n");

    dap_cli_server_cmd_add ("policy", com_policy, NULL, "Policy commands", dap_chain_node_cli_cmd_id_from_str("policy"),
                "policy activate - prepare policy activate decree\n"
                "\t[execute] - used to create policy decree, otherwise show policy decree draft\n"
                "\t-net <net_name>\n"
                "\t-num <policy_num>\n"
                "\t[-ts_start <dd/mm/yy-H:M:S>] - date to start policy\n"
                "\t[{\n\t\t-block_start <block_num> - block num to start policy\n"
                "\t\t-chain <chain_name> - chain name to check blocks num\n\t}]\n"
                "\t-certs <cert1[,cert2,...,certN]> - list signing certs\n"
                "policy deactivate - prepare policy deactivate decree\n"
                "\t[execute] - used to create policy decree, otherwise show policy decree draft\n"
                "\t-net <net_name>\n"
                "\t-num <num1[,num2,...,numN]> - deactivated policy list\n"
                "\t-certs <cert1[,cert2,...,certN]> - list signing certs\n"
                "policy find - find info about policy in net\n"
                "\t-net <net_name>\n"
                "\t-num <policy_num>\n"
                "policy list - show all policies from table in net\n"
                "\t-net <net_name>\n");
    // Exit - always last!
    dap_cli_server_cmd_add ("exit", com_exit, NULL, "Stop application and exit", dap_chain_node_cli_cmd_id_from_str("exit"),
                "exit\n" );
    dap_notify_srv_set_callback_new(dap_notify_new_client_send_info);
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
    dap_chain_node_sync_client_deinit();
    dap_chain_node_rpc_deinit();
}

int  s_print_for_mempool_list(dap_json_rpc_response_t* response, char **cmd_param, int cmd_cnt){
    dap_return_val_if_pass(!response || !response->result_json_object, -1);
	// Raw JSON flag

	bool l_table_mode = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") != -1;
	if (!l_table_mode) { dap_json_print_object(response->result_json_object, stdout, 0); return 0; }
	if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "list") == -1)
		return -2;

	dap_json_t *json_obj_response = dap_json_array_get_idx(response->result_json_object, 0);
	if (!json_obj_response)
		return -3;

	dap_json_t *j_obj_net_name = NULL, *j_arr_chains = NULL;
	dap_json_object_get_ex(json_obj_response, "net", &j_obj_net_name);
	dap_json_object_get_ex(json_obj_response, "chains", &j_arr_chains);
	if (!j_arr_chains || dap_json_get_type(j_arr_chains) != DAP_JSON_TYPE_ARRAY)
		return -4;

	int chains_count = dap_json_array_length(j_arr_chains);
	for (int i = 0; i < chains_count; i++) {
		dap_json_t *json_obj_chain = dap_json_array_get_idx(j_arr_chains, i);
		if (!json_obj_chain)
			continue;

		dap_json_t *j_obj_chain_name = NULL, *j_obj_removed = NULL, *j_arr_datums = NULL, *j_obj_total = NULL;
		dap_json_object_get_ex(json_obj_chain, "name", &j_obj_chain_name);
		dap_json_object_get_ex(json_obj_chain, "removed", &j_obj_removed);
		dap_json_object_get_ex(json_obj_chain, "datums", &j_arr_datums);
		dap_json_object_get_ex(json_obj_chain, "total", &j_obj_total);

		if (j_obj_removed && j_obj_chain_name && j_obj_net_name) {
			printf("Removed %d records from the %s chain mempool in %s network.\n",
					(int)dap_json_get_int64(j_obj_removed),
					dap_json_get_string(j_obj_chain_name),
					dap_json_get_string(j_obj_net_name));
		}

		printf("________________________________________________________________________________________________________________"
            "________________\n");
		printf("  Hash \t\t\t\t\t\t\t\t     | %-22s | %-31s |\n","Datum type", "Time create");

		if (j_arr_datums && dap_json_get_type(j_arr_datums) == DAP_JSON_TYPE_ARRAY) {
			int datums_count = dap_json_array_length(j_arr_datums);
			for (int j = 0; j < datums_count; j++) {
				dap_json_t *j_obj_datum = dap_json_array_get_idx(j_arr_datums, j);
				if (!j_obj_datum)
					continue;

				dap_json_t *j_hash = NULL, *j_type = NULL, *j_created = NULL;
				/* hash (v1: "hash", v2: "datum_hash") */
				if (!dap_json_object_get_ex(j_obj_datum, "hash", &j_hash))
					dap_json_object_get_ex(j_obj_datum, "datum_hash", &j_hash);
				/* type (v1: "type", v2: "datum_type") */
				if (!dap_json_object_get_ex(j_obj_datum, "type", &j_type))
					dap_json_object_get_ex(j_obj_datum, "datum_type", &j_type);
				/* created object { str, time_stamp } */
				dap_json_object_get_ex(j_obj_datum, "created", &j_created);

				const char *hash_str = j_hash ? dap_json_get_string(j_hash) : "N/A";
				const char *type_str = j_type ? dap_json_get_string(j_type) : "N/A";
				const char *created_str = "N/A";
				char ts_buf[64];
				if (j_created && dap_json_get_type(j_created) == DAP_JSON_TYPE_OBJECT) {
					dap_json_t *j_created_str = NULL, *j_created_ts = NULL;
					if (dap_json_object_get_ex(j_created, "str", &j_created_str) && j_created_str) {
						created_str = dap_json_get_string(j_created_str);
					} else if (dap_json_object_get_ex(j_created, "time_stamp", &j_created_ts) && j_created_ts) {
						/* print numeric timestamp if readable string is absent */
						snprintf(ts_buf, sizeof(ts_buf), "%"DAP_INT64_FORMAT, dap_json_get_int64(j_created_ts));
						created_str = ts_buf;
					}
				}

				printf("  %s | %-22s | %-31s |\n", hash_str, type_str, created_str);
			}
		} else {
			printf("  No datums\n");
		}

		printf("_____________________________________________________________________"
            "|________________________|_________________________________|\n\n");

		if (j_obj_total)
			printf("  total: %s\n", dap_json_get_string(j_obj_total));
	}

	return 0;
}

/**
 * @brief s_print_for_ledger_list
 * Pretty-printer for 'ledger list' responses.
 * Handles 'coins' subcommand with flexible JSON formats:
 *  - Array of token objects (optionally followed by {limit}/{offset})
 *  - Object mapping ticker to token object
 * Uses json_object_object_foreach where keys themselves carry semantics (e.g., ticker).
 *
 * @param response JSON RPC response object
 * @param cmd_param CLI command parameters
 * @param cmd_cnt CLI parameters count
 * @return int 0 on success, negative on error
 */
static int s_print_for_ledger_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    dap_return_val_if_pass(!response || !response->result_json_object, -1);
    // Table mode flag: -h. If not present, print raw JSON by default
    bool l_table_mode = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") != -1;
    if (!l_table_mode) { dap_json_print_object(response->result_json_object, stdout, 0); return 0; }
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "list") == -1)
        return -2;
    // coins
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "coins") != -1) {
        if (dap_json_get_type(response->result_json_object) != DAP_JSON_TYPE_ARRAY)
            return -3;

        dap_json_t *root0 = dap_json_array_get_idx(response->result_json_object, 0);
        if (!root0)
            return -4;

        // There are two common formats observed:
        // 1) Array of token objects [{...token fields...}, {limit:...}, {offset:...}]
        // 2) Object mapping tickers to token objects { TICKER: {...}, ... }
        // We will detect and handle both. Field names may vary between versions.

        // Case 1: array of objects where each token is an object with field token_name or subtype/supply, etc.
        if (dap_json_get_type(root0) == DAP_JSON_TYPE_ARRAY) {
            int arr_len = dap_json_array_length(root0);
            if (arr_len <= 0) { printf("No coins found\n"); return 0; }

            printf("__________________________________________________________________________________________________________"
                "____________________________\n");
            printf("  %-15s|  %-7s| %-9s|  %-45s|  %-45s|\n",
                   "Token Ticker", "Type", "Decimals", "Total Supply", "Current Supply");
            printf("__________________________________________________________________________________________________________"
                "____________________________\n");

            int printed = 0;
            for (int i = 0; i < arr_len; i++) {
                dap_json_t *it = dap_json_array_get_idx(root0, i);
                if (!it || dap_json_get_type(it) != DAP_JSON_TYPE_OBJECT)
                    continue;

                // Skip control objects like {limit:...} or {offset:...}
                dap_json_t *limit = NULL, *offset = NULL;
                if (dap_json_object_get_ex(it, "limit", &limit) || dap_json_object_get_ex(it, "offset", &offset))
                    continue;

                const char *ticker = NULL;
                const char *type_str = "N/A";
                const char *supply_total = "N/A";
                const char *supply_current = "N/A";
                int decimals = 0;

                dap_json_t *j_ticker = NULL, *j_type = NULL, *j_dec = NULL, *j_supply_total = NULL, *j_supply_current = NULL;
                // keys vary by version
                if (dap_json_object_get_ex(it, "token_name", &j_ticker) ||
                    dap_json_object_get_ex(it, "-->Token name", &j_ticker))
                    ticker = dap_json_get_string(j_ticker);
                if (dap_json_object_get_ex(it, "subtype", &j_type) ||
                    dap_json_object_get_ex(it, "type", &j_type))
                    type_str = dap_json_get_string(j_type);
                if (dap_json_object_get_ex(it, "decimals", &j_dec) ||
                    dap_json_object_get_ex(it, "Decimals", &j_dec))
                    decimals = (int)dap_json_get_int64(j_dec);
                if (dap_json_object_get_ex(it, "supply_total", &j_supply_total) ||
                    dap_json_object_get_ex(it, "Supply total", &j_supply_total))
                    supply_total = dap_json_get_string(j_supply_total);
                if (dap_json_object_get_ex(it, "supply_current", &j_supply_current) ||
                    dap_json_object_get_ex(it, "Supply current", &j_supply_current))
                    supply_current = dap_json_get_string(j_supply_current);

                if (!ticker) {
                    // If ticker not found, use UNKNOWN
                    // (Inferring from keys would require callback, skip for simplicity)
                    ticker = "UNKNOWN";
                }

                printf("  %-15s|  %-7s|    %-6d|  %-45s|  %-45s|\n",
                       ticker, type_str, decimals, supply_total, supply_current);
                printed++;
            }
            if (!printed)
                printf("No coins found\n");
            return 0;
        }

        // Case 2: object mapping ticker -> token object
        if (dap_json_get_type(root0) == DAP_JSON_TYPE_OBJECT) {
            printf("__________________________________________________________________________________________________________\n");
            printf("  %-15s|  %-7s|    %-6s|  %-45s|  %-45s|\n",
                   "Token Ticker", "Type", "Decimals", "Total Supply", "Current Supply");
            printf("__________________________________________________________________________________________________________\n");

            // Use callback for iterating (reuse s_token_list_callback or create new one)
            // For simplicity, just print a message that this format is not fully supported
            printf("Object format detected. Use raw JSON output (-h flag removed) for full details.\n");
            dap_json_print_object(root0, stdout, 0);
            return 0;
        }

        // Fallback
        dap_json_print_object(response->result_json_object, stdout, 0);
        return 0;
    }

    // threshold
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "threshold") != -1) {
        bool l_full = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-full") != -1;
        if (dap_json_get_type(response->result_json_object) != DAP_JSON_TYPE_ARRAY) {
            dap_json_print_object(response->result_json_object, stdout, 0);
            return 0;
        }
        dap_json_t *json_obj_array = dap_json_array_get_idx(response->result_json_object, 0);
        if (!json_obj_array) {
            printf("Response array is empty\n");
            return -3;
        }
        int result_count = dap_json_array_length(json_obj_array);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
        if (l_full) {
            printf("_________________________________________________________________________________________________________________"
                   "_________________________________________________________________________________________________________________\n");
            printf(" %-66s | %-31s | %-12s |\n", "Tx Hash", "Time Created", "Items Size");
        } else {
            printf("________________________________________________________________________________________________________\n");
            printf(" %-15s | %-31s | %-12s |\n", "Tx Hash", "Time Created", "Items Size");
        }
        char hash_buffer[16];
        for (int i = 0; i < result_count; i++) {
            dap_json_t *json_obj_result = dap_json_array_get_idx(json_obj_array, i);
            if (!json_obj_result)
                continue;
            // Skip meta objects like {limit}/{offset}
            dap_json_t *j_meta = NULL;
            if (dap_json_object_get_ex(json_obj_result, "limit", &j_meta) ||
                dap_json_object_get_ex(json_obj_result, "offset", &j_meta))
                continue;

            dap_json_t *j_tx_hash = NULL, *j_time_created = NULL, *j_items_size = NULL;
            // Versioned key for tx hash
            if (!dap_json_object_get_ex(json_obj_result, "tx_hash", &j_tx_hash))
                dap_json_object_get_ex(json_obj_result, "Ledger thresholded tx_hash_fast", &j_tx_hash);
            dap_json_object_get_ex(json_obj_result, "time_created", &j_time_created);
            dap_json_object_get_ex(json_obj_result, "tx_item_size", &j_items_size);

            const char *tx_hash_full = j_tx_hash ? dap_json_get_string(j_tx_hash) : NULL;
            const char *tx_hash_short = tx_hash_full;
            if (!l_full && tx_hash_full && strlen(tx_hash_full) > 15) {
                strncpy(hash_buffer, tx_hash_full + strlen(tx_hash_full) - 15, 15);
                hash_buffer[15] = '\0';
                tx_hash_short = hash_buffer;
            }
            printf(" %-15s | %-31s | %-12s |\n",
                   l_full ? (tx_hash_full ? tx_hash_full : "-") : (tx_hash_short ? tx_hash_short : "-"),
                   j_time_created ? dap_json_get_string(j_time_created) : "-",
                   j_items_size ? dap_json_get_string(j_items_size) : "-");
        }
        return 0;
    }

    // balance
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "balance") != -1) {
        bool l_full = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-full") != -1;
        if (dap_json_get_type(response->result_json_object) != DAP_JSON_TYPE_ARRAY) {
            dap_json_print_object(response->result_json_object, stdout, 0);
            return 0;
        }
        dap_json_t *json_obj_array = dap_json_array_get_idx(response->result_json_object, 0);
        if (!json_obj_array) {
            printf("Response array is empty\n");
            return -3;
        }
        int result_count = dap_json_array_length(json_obj_array);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
        if (l_full) {
            printf("_________________________________________________________________________________________________________________"
                   "____________________________________________________________________________________________\n");
            printf(" %-120s | %-10s | %-66s |\n", "Balance Key", "Token", "Balance");
        } else {
            printf("________________________________________________________________________________________________________"
            "__________\n");
            printf(" %-30s | %-10s | %-66s |\n", "Balance Key", "Token", "Balance");
        }
        for (int i = 0; i < result_count; i++) {
            dap_json_t *json_obj_result = dap_json_array_get_idx(json_obj_array, i);
            if (!json_obj_result)
                continue;
            // Skip meta objects like {limit}/{offset}
            dap_json_t *j_meta = NULL;
            if (dap_json_object_get_ex(json_obj_result, "limit", &j_meta) ||
                dap_json_object_get_ex(json_obj_result, "offset", &j_meta))
                continue;

            dap_json_t *j_key = NULL, *j_token = NULL, *j_balance = NULL;
            if (!dap_json_object_get_ex(json_obj_result, "balance_key", &j_key))
                dap_json_object_get_ex(json_obj_result, "Ledger balance key", &j_key);
            dap_json_object_get_ex(json_obj_result, "token_ticker", &j_token);
            dap_json_object_get_ex(json_obj_result, "balance", &j_balance);
            int key_width = l_full ? 120 : 30;
            const char *key_str_full = j_key ? dap_json_get_string(j_key) : "-";            

            printf(" %-*s | %-10s | %-66s |\n",
                   key_width,
                   l_full ? key_str_full : key_str_full+85,
                   j_token ? dap_json_get_string(j_token) : "-",
                   j_balance ? dap_json_get_string(j_balance) : "-");
        }
        return 0;
    }

    // other ledger list subcmds handled elsewhere or printed raw
    dap_json_print_object(response->result_json_object, stdout, 0);
    return 0;
}

// Helper structure for token list iteration
typedef struct {
    int *total_tokens;
    bool l_full;
} token_list_ctx_t;

// Callback for counting object keys
static void s_count_keys_callback(const char* key, dap_json_t* value, void* user_data) {
    (void)key; (void)value;
    int *count = (int*)user_data;
    (*count)++;
}

// Callback for printing group list
static void s_print_group_callback(const char* key, dap_json_t* val, void* user_data) {
    (void)user_data;
    printf(" - %s: %" DAP_INT64_FORMAT "\n", key, dap_json_get_int64(val));
}

// Callback for iterating through tokens
static void s_token_list_callback(const char* ticker, dap_json_t* token_obj, void* user_data) {
    token_list_ctx_t *ctx = (token_list_ctx_t*)user_data;
    (*ctx->total_tokens)++;
    
    dap_json_t *current_state = NULL;
    dap_json_t *declarations = NULL;
    dap_json_t *updates = NULL;
    
    dap_json_object_get_ex(token_obj, "current_state", &current_state);
    if (!current_state)
        dap_json_object_get_ex(token_obj, "current state", &current_state);
    dap_json_object_get_ex(token_obj, "declarations", &declarations);
    dap_json_object_get_ex(token_obj, "updates", &updates);
    
    // Extract token info from current_state
    const char *total_supply = "N/A";
    const char *current_supply = "N/A";
    const char *token_type = "N/A";
    const char *current_signs = "N/A";                
    const char *decl_status = "N/A";
    const char *decl_hash_short = "N/A";
    int decimals = 0;
    char hash_buffer[12] = {0};
    
    if (current_state) {
        dap_json_t *total_supply_obj = NULL;
        dap_json_t *current_supply_obj = NULL;
        dap_json_t *type_obj = NULL;
        dap_json_t *signs_obj = NULL;
        dap_json_t *decimals_obj = NULL;
        
        if (dap_json_object_get_ex(current_state, "Supply total", &total_supply_obj))
            total_supply = dap_json_get_string(total_supply_obj);
        if (dap_json_object_get_ex(current_state, "Supply current", &current_supply_obj))
            current_supply = dap_json_get_string(current_supply_obj);
        if (dap_json_object_get_ex(current_state, "type", &type_obj))
            token_type = dap_json_get_string(type_obj);
        if (dap_json_object_get_ex(current_state, "Auth signs valid", &signs_obj))
            current_signs = dap_json_get_string(signs_obj);
        if (dap_json_object_get_ex(current_state, "Decimals", &decimals_obj))
            decimals = (int)dap_json_get_int64(decimals_obj);
    }
    
    // Extract declaration info (get latest declaration)
    if (declarations && dap_json_array_length(declarations) > 0) {
        dap_json_t *latest_decl = dap_json_array_get_idx(declarations, 
            dap_json_array_length(declarations) - 1);
        if (latest_decl) {
            dap_json_t *status_obj = NULL;
            dap_json_t *hash_obj = NULL;
            
            if (dap_json_object_get_ex(latest_decl, "status", &status_obj))
                decl_status = dap_json_get_string(status_obj);
            
            dap_json_t *datum_obj = NULL;
            if (dap_json_object_get_ex(latest_decl, "Datum", &datum_obj)) {
                if (dap_json_object_get_ex(datum_obj, "hash", &hash_obj)) {
                    const char *full_hash = dap_json_get_string(hash_obj);
                    decl_hash_short = full_hash;
                    if (!ctx->l_full && full_hash && strlen(full_hash) > 10) {
                        strncpy(hash_buffer, full_hash + strlen(full_hash) - 10, 10);
                        hash_buffer[10] = '\0';
                        decl_hash_short = hash_buffer;
                    } else if (full_hash) {
                        decl_hash_short = full_hash;
                    }
                }
            }
        }
    }
    
    int decl_count = declarations ? dap_json_array_length(declarations) : 0;
    int upd_count = updates ? dap_json_array_length(updates) : 0;
    
    printf("  %-15s|  %-7s|    %-6d|     %-10s|      %-9d|   %-7d|   %-9s|  %-*s|  %-40s|  %-40s|\n",
        ticker,
        token_type,
        decimals,
        current_signs,
        decl_count,
        upd_count,
        decl_status,
        (int)strlen(decl_hash_short)+1,
        decl_hash_short,
        total_supply,
        current_supply
    );
}

static int s_print_for_token_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    if (!response || !response->result_json_object) {
        printf("Response is empty\n");
        return -1;
    }
    printf("tmp\n");
    bool l_table_mode = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") != -1;
    bool l_full = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-full") != -1;

    if (!l_table_mode) { dap_json_print_object(response->result_json_object, stdout, 0); return 0; }

    
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "list") == -1)
        return -2;
    
    if (dap_json_get_type(response->result_json_object) == DAP_JSON_TYPE_ARRAY) {        
        int result_count = dap_json_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
                
        dap_json_t *json_obj_main = dap_json_array_get_idx(response->result_json_object, 0);
        dap_json_t *j_object_tokens = NULL;
        
        // Get TOKENS or tokens array
        if (!dap_json_object_get_ex(json_obj_main, "TOKENS", &j_object_tokens) &&
            !dap_json_object_get_ex(json_obj_main, "tokens", &j_object_tokens)) {
            printf("TOKENS field not found\n");
            return -4;
        }
        
        int chains_count = dap_json_array_length(j_object_tokens);
        if (chains_count <= 0) {
            printf("No tokens found\n");
            return -5;
        }
        
        // Print table header
        if (l_full) {
            printf("__________________________________________________________________________________________________________________________________________________________________________________"
                   "_________________________________________________________________________\n");
            printf("  %-15s|  %-7s| %-6s | %-13s | %-13s | %-8s | %-11s| %-68s| %-41s| %-41s|\n",
                   "Token Ticker", "Type", "Decimals", "Current Signs", "Declarations", "Updates", "Decl Status", "Decl Hash (full)", "Total Supply", "Current Supply");
        } else {
            printf("__________________________________________________________________________________________________________________________________________________________________________________"
            "________________\n");
            printf("  %-15s|  %-7s| %-6s | %-13s | %-13s | %-8s | %-11s| %-12s| %-41s| %-41s|\n",
                   "Token Ticker", "Type", "Decimals", "Current Signs", "Declarations", "Updates", "Decl Status", "Decl Hash", "Total Supply", "Current Supply");
        }
        
        int total_tokens = 0;
        token_list_ctx_t ctx = { .total_tokens = &total_tokens, .l_full = l_full };
        
        // Iterate through chains
        for (int chain_idx = 0; chain_idx < chains_count; chain_idx++) {
            dap_json_t *chain_tokens = dap_json_array_get_idx(j_object_tokens, chain_idx);
            if (!chain_tokens)
                continue;
                
            // Iterate through tokens in this chain using callback
            dap_json_object_foreach(chain_tokens, s_token_list_callback, &ctx);
        }
        
        printf("\nTotal tokens: %d\n", total_tokens);
        
        // Show tokens_count if available
        dap_json_t *tokens_count_obj = NULL;
        if (dap_json_object_get_ex(json_obj_main, "tokens_count", &tokens_count_obj)) {
            printf("Tokens count: %s\n", dap_json_get_string(tokens_count_obj));
        }
        
    } else {
        dap_json_print_object(response->result_json_object, stdout, 0);
        return -6;
    }
    return 0;
}

/**
 * @brief s_print_for_tx_history_all
 * JSON parser for tx_history command responses
 * Handles different types of tx_history responses:
 * - Transaction history list with summary (for -all and -addr)
 * - Single transaction (for -tx hash)
 * - Transaction count (for -count)
 * @param response JSON RPC response object
 * @param cmd_param Command parameters array
 * @param cmd_cnt Count of command parameters
 * @return int 0 on success, negative on error
 */
static int s_print_for_tx_history_all(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt)
{
	dap_return_val_if_pass(!response || !response->result_json_object, -1);
    bool l_table_mode = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") != -1;
    if (!l_table_mode) { dap_json_print_object(response->result_json_object, stdout, 0); return 0; }
	if (dap_json_get_type(response->result_json_object) == DAP_JSON_TYPE_ARRAY) {
		int result_count = dap_json_array_length(response->result_json_object);
		if (result_count <= 0) {
			printf("Response array is empty\n");
			return -2;
		}

		// Special handling for -addr and -w: array[0] is tx list with address header, array[1] is summary
		if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-addr") != -1 ||
			dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-w") != -1) {
			dap_json_t *tx_array = dap_json_array_get_idx(response->result_json_object, 0);
			dap_json_t *summary_obj = dap_json_array_get_idx(response->result_json_object, 1);
			if (tx_array && dap_json_get_type(tx_array) == DAP_JSON_TYPE_ARRAY) {
				// Print address header if present as the first element
				dap_json_t *first_el = dap_json_array_get_idx(tx_array, 0);
				dap_json_t *addr_obj = NULL;
				if (first_el && dap_json_get_type(first_el) == DAP_JSON_TYPE_OBJECT &&
				   (dap_json_object_get_ex(first_el, "addr", &addr_obj) ||
				    dap_json_object_get_ex(first_el, "address", &addr_obj))) {
					printf("Address: %s\n", dap_json_get_string(addr_obj));
				}

				printf("_________________________________________________________________________________________________________________"
					"________________________________________________\n");
				printf(" # \t| Hash \t\t\t\t\t\t\t\t     | Status   | Action \t  | Service \t     | Time create\n");
				printf("_________________________________________________________________________________________________________________"
					"________________________________________________\n");

				char *l_limit = NULL; char *l_offset = NULL; int row_num = 0;
				for (size_t i = 0; i < (size_t)dap_json_array_length(tx_array); i++) {
					dap_json_t *tx_obj = dap_json_array_get_idx(tx_array, (int)i);
					if (!tx_obj || dap_json_get_type(tx_obj) != DAP_JSON_TYPE_OBJECT)
						continue;
					// Skip header element with addr/address
					dap_json_t *tmp = NULL;
					if (dap_json_object_get_ex(tx_obj, "addr", &tmp) || dap_json_object_get_ex(tx_obj, "address", &tmp)){
						continue;
					}
					// Handle limit/offset info
					dap_json_t *j_obj_lim = NULL, *j_obj_off = NULL;
					if (dap_json_object_get_ex(tx_obj, "limit", &j_obj_lim)) {
						dap_json_object_get_ex(tx_obj, "offset", &j_obj_off);
						l_limit = dap_json_get_int64(j_obj_lim) ? dap_strdup_printf("%"DAP_INT64_FORMAT, dap_json_get_int64(j_obj_lim)) : dap_strdup_printf("unlimit");
						if (j_obj_off)
							l_offset = dap_strdup_printf("%"DAP_INT64_FORMAT, dap_json_get_int64(j_obj_off));
						continue;
					}

					dap_json_t *hash_obj = NULL, *status_obj = NULL, *action_obj = NULL, *service_obj = NULL, *created_obj = NULL;
					if (dap_json_object_get_ex(tx_obj, "hash", &hash_obj) &&
						dap_json_object_get_ex(tx_obj, "status", &status_obj) &&
						dap_json_object_get_ex(tx_obj, "action", &action_obj) &&
						dap_json_object_get_ex(tx_obj, "service", &service_obj) &&
						dap_json_object_get_ex(tx_obj, "tx_created", &created_obj)) {
						row_num++;
						printf("%d\t| %-60s | %s\t| %-15s |  %-16s| %s\t|\n",
							row_num,
							dap_json_get_string(hash_obj),
							dap_json_get_string(status_obj),
							dap_json_get_string(action_obj),
							dap_json_get_string(service_obj),
							dap_json_get_string(created_obj));
					}
				}
				printf("_________________________________________________________________________________________________________________"
					"________________________________________________\n");
				if (l_limit) { printf("\tlimit: %s \n", l_limit); DAP_DELETE(l_limit); }
				if (l_offset) { printf("\toffset: %s \n", l_offset); DAP_DELETE(l_offset); }
				if (summary_obj && dap_json_get_type(summary_obj) == DAP_JSON_TYPE_OBJECT) {
					dap_json_t *tx_sum_obj = NULL, *accepted_obj = NULL, *rejected_obj = NULL;
					dap_json_object_get_ex(summary_obj, "tx_sum", &tx_sum_obj);
					dap_json_object_get_ex(summary_obj, "accepted_tx", &accepted_obj);
					dap_json_object_get_ex(summary_obj, "rejected_tx", &rejected_obj);
					if (tx_sum_obj || accepted_obj || rejected_obj)
						printf("Total: %d transactions (Accepted: %d, Rejected: %d)\n",
							tx_sum_obj ? (int)dap_json_get_int64(tx_sum_obj) : row_num,
							accepted_obj ? (int)dap_json_get_int64(accepted_obj) : 0,
							rejected_obj ? (int)dap_json_get_int64(rejected_obj) : 0);
				}
				return 0;
			}
		}

		// Check if this is a count response (single object with count)
		if (result_count == 1) {
			dap_json_t *first_obj = dap_json_array_get_idx(response->result_json_object, 0);
			dap_json_t *count_obj = NULL;
			
			// Check for count response (version 1 or 2)
			if (dap_json_object_get_ex(first_obj, "Number of transaction", &count_obj) ||
			    dap_json_object_get_ex(first_obj, "total_tx_count", &count_obj)) {
                printf("Total transactions count: %"DAP_INT64_FORMAT"\n", dap_json_get_int64(count_obj));
				return 0;
			}
		}

		// Handle transaction history list (should have 2 elements: transactions array + summary)
		if (result_count >= 2) {
			dap_json_t *tx_array = dap_json_array_get_idx(response->result_json_object, 0);
			dap_json_t *summary_obj = dap_json_array_get_idx(response->result_json_object, 1);			

			// Print transactions table header
			printf("_________________________________________________________________________________________________________________"
                "________________________________________________\n");
			printf(" # \t| Hash \t\t\t\t\t\t\t\t     | Status   | Action \t  | Token \t     | Time create\n");
			printf("_________________________________________________________________________________________________________________"
                "________________________________________________\n");

			// Print transaction list
			if (dap_json_get_type(tx_array) == DAP_JSON_TYPE_ARRAY) {
                char *l_limit = NULL;
                char *l_offset = NULL;
				int tx_count = dap_json_array_length(tx_array);
				for (int i = 0; i < tx_count; i++) {
					dap_json_t *tx_obj = dap_json_array_get_idx(tx_array, i);
					if (!tx_obj) continue;

					dap_json_t *tx_num_obj = NULL, *hash_obj = NULL;
					dap_json_t *status_obj = NULL, *action_obj = NULL;
					dap_json_t *token_obj = NULL, *j_obj_lim = NULL, *j_obj_off = NULL;
                    dap_json_t *j_obj_create = NULL;

					// Get transaction fields (support both version 1 and 2)
                    if ((dap_json_object_get_ex(tx_obj, "tx number", &tx_num_obj) ||
					    dap_json_object_get_ex(tx_obj, "tx_num", &tx_num_obj)) &&
					    dap_json_object_get_ex(tx_obj, "hash", &hash_obj) &&
					    dap_json_object_get_ex(tx_obj, "status", &status_obj) &&
					    dap_json_object_get_ex(tx_obj, "action", &action_obj) &&
					    dap_json_object_get_ex(tx_obj, "token ticker", &token_obj) &&
                        dap_json_object_get_ex(tx_obj, "tx created", &j_obj_create)) {                            

					    printf("%s\t| %-60s | %s\t| %-15s |  %-16s| %s\t|\n",
						   dap_json_get_string(tx_num_obj),
						   dap_json_get_string(hash_obj),
						   dap_json_get_string(status_obj),
						   dap_json_get_string(action_obj),
						   dap_json_get_string(token_obj),
                           dap_json_get_string(j_obj_create));
                    } else if (dap_json_object_get_ex(tx_obj, "limit", &j_obj_lim)) {
                        dap_json_object_get_ex(tx_obj, "offset", &j_obj_off);
                        l_limit = dap_json_get_int64(j_obj_lim) ? dap_strdup_printf("%"DAP_INT64_FORMAT,dap_json_get_int64(j_obj_lim)) : dap_strdup_printf("unlimit");
                        if (j_obj_off)
                            l_offset = dap_strdup_printf("%"DAP_INT64_FORMAT,dap_json_get_int64(j_obj_off));
                    } else {
                        dap_json_print_object(tx_obj, stdout, 0);
                    }
				}
                printf("_________________________________________________________________________________________________________________"
                    "________________________________________________\n");
                if (l_limit) {
                    printf("\tlimit: %s \n", l_limit);
                    DAP_DELETE(l_limit);
                }
                if (l_offset) {
                    printf("\toffset: %s \n", l_offset);
                    DAP_DELETE(l_offset);
                }
			}

            // Print summary information
			if (summary_obj) {
				dap_json_t *network_obj = NULL, *chain_obj = NULL;
				dap_json_t *tx_sum_obj = NULL, *accepted_obj = NULL, *rejected_obj = NULL;
				
				dap_json_object_get_ex(summary_obj, "network", &network_obj);
				dap_json_object_get_ex(summary_obj, "chain", &chain_obj);
				dap_json_object_get_ex(summary_obj, "tx_sum", &tx_sum_obj);
				dap_json_object_get_ex(summary_obj, "accepted_tx", &accepted_obj);
				dap_json_object_get_ex(summary_obj, "rejected_tx", &rejected_obj);

				printf("\n=== Transaction History ===\n");
				if (network_obj && chain_obj) {
					printf("Network: %s, Chain: %s\n", 
						   dap_json_get_string(network_obj),
						   dap_json_get_string(chain_obj));
				}
				if (tx_sum_obj && accepted_obj && rejected_obj) {
					printf("Total: %d transactions (Accepted: %d, Rejected: %d)\n\n",
						   (int)dap_json_get_int64(tx_sum_obj),
						   (int)dap_json_get_int64(accepted_obj),
						   (int)dap_json_get_int64(rejected_obj));
				}
			}

		} else {
			// Single transaction or unknown format - fallback to JSON print
			dap_json_print_object(response->result_json_object, stdout, 0);
		}
	} else {
		// Single object response - could be a single transaction
		dap_json_t *hash_obj = NULL;
		if (dap_json_object_get_ex(response->result_json_object, "hash", &hash_obj)) {
			// This looks like a single transaction
			printf("\n=== Single Transaction ===\n");
			dap_json_print_object(response->result_json_object, stdout, 0);
		} else {
			// Unknown format
			dap_json_print_object(response->result_json_object, stdout, 0);
		}
	}

	return 0;
}

/**
 * @brief s_print_for_global_db
 * Simple JSON printer for global_db command responses. It tries to format
 * known subcommands (group_list, get_keys, record get/pin/unpin, read/write/delete/drop_table, flush),
 * otherwise falls back to printing the JSON object/array as is.
 *
 * @param response JSON RPC response object
 * @param cmd_param Command parameters array
 * @param cmd_cnt Count of command parameters
 * @return int 0 on success, negative on error
 */
static int s_print_for_global_db(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt)
{
    // Raw JSON flag
    dap_return_val_if_pass(!response || !response->result_json_object, -1);

    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") == -1) {
        dap_json_print_object(response->result_json_object, stdout, 0);
        return 0;
    }

    // group_list: can be an array of objects { group_name: count } or an object { group_name: count }
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "group_list") != -1) {
        if (dap_json_get_type(response->result_json_object) == DAP_JSON_TYPE_ARRAY) {
            int len = dap_json_array_length(response->result_json_object);
            if (len <= 0) { printf("Response array is empty\n"); return -2; }
            dap_json_t *obj = dap_json_array_get_idx(response->result_json_object, 0);
            dap_json_t *arr = NULL, *total = NULL;
            if (obj && dap_json_get_type(obj) == DAP_JSON_TYPE_OBJECT) {
                // Support both spaced and underscored keys from different implementations
                dap_json_object_get_ex(obj, "group_list", &arr);
                if (!arr) dap_json_object_get_ex(obj, "group list", &arr);
                dap_json_object_get_ex(obj, "total_count", &total);
                if (!total) dap_json_object_get_ex(obj, "total count", &total);

                if (arr) {
                    int64_t groups_total = 0;
                    if (total)
                        groups_total = dap_json_get_int64(total);
                    else if (dap_json_get_type(arr) == DAP_JSON_TYPE_ARRAY)
                        groups_total = (int64_t)dap_json_array_length(arr);
                    else if (dap_json_get_type(arr) == DAP_JSON_TYPE_OBJECT) {
                        int count = 0;
                        dap_json_object_foreach(arr, s_count_keys_callback, &count);
                        groups_total = (int64_t)count;
                    }

                    printf("Groups (total: %" DAP_INT64_FORMAT "):\n", groups_total);

                    if (dap_json_get_type(arr) == DAP_JSON_TYPE_ARRAY) {
                        for (size_t i = 0; i < (size_t)dap_json_array_length(arr); i++) {
                            dap_json_t *it = dap_json_array_get_idx(arr, (int)i);
                            if (it && dap_json_get_type(it) == DAP_JSON_TYPE_OBJECT) {
                                dap_json_object_foreach(it, s_print_group_callback, NULL);
                            }
                        }
                        return 0;
                    } else if (dap_json_get_type(arr) == DAP_JSON_TYPE_OBJECT) {
                        dap_json_object_foreach(arr, s_print_group_callback, NULL);
                        return 0;
                    }
                }
            }
            // fallback
            dap_json_print_object(response->result_json_object, stdout, 0);
            return 0;
        }
    }

    // get_keys: array with one object containing keys_list
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "get_keys") != -1) {
        if (dap_json_get_type(response->result_json_object) == DAP_JSON_TYPE_ARRAY) {
            dap_json_t *obj = dap_json_array_get_idx(response->result_json_object, 0);
            dap_json_t *group = NULL, *keys = NULL;
            if (obj && dap_json_get_type(obj) == DAP_JSON_TYPE_OBJECT) {
                dap_json_object_get_ex(obj, "group_name", &group);
                if (!group) dap_json_object_get_ex(obj, "group name", &group);
                dap_json_object_get_ex(obj, "keys_list", &keys);
                if (!keys) dap_json_object_get_ex(obj, "keys list", &keys);
                if (keys && dap_json_get_type(keys) == DAP_JSON_TYPE_ARRAY) {
                    printf("Keys in group %s:\n", group ? dap_json_get_string(group) : "<unknown>");
                    for (size_t i = 0; i < (size_t)dap_json_array_length(keys); i++) {
                        dap_json_t *it = dap_json_array_get_idx(keys, (int)i);
                        dap_json_t *k = NULL, *ts = NULL, *type = NULL;
                        if (it && dap_json_get_type(it) == DAP_JSON_TYPE_OBJECT) {
                            dap_json_object_get_ex(it, "key", &k);
                            dap_json_object_get_ex(it, "time", &ts);
                            dap_json_object_get_ex(it, "type", &type);
                            printf(" - %s (%s) [%s]\n",
                                   k ? dap_json_get_string(k) : "<no key>",
                                   ts ? dap_json_get_string(ts) : "-",
                                   type ? dap_json_get_string(type) : "-");
                        }
                    }
                    return 0;
                }
            }
        }
        dap_json_print_object(response->result_json_object, stdout, 0);
        return 0;
    }
    
    // clusters: display list of global_db clusters
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "clusters") != -1) {
        if (dap_json_get_type(response->result_json_object) != DAP_JSON_TYPE_ARRAY) {
            dap_json_print_object(response->result_json_object, stdout, 0);
            return 0;
        }
        
        dap_json_t *obj = dap_json_array_get_idx(response->result_json_object, 0);
        if (!obj || dap_json_get_type(obj) != DAP_JSON_TYPE_OBJECT) {
            printf("Response format error\n");
            return -2;
        }
        
        dap_json_t *clusters_arr = NULL, *total = NULL;
        dap_json_object_get_ex(obj, "clusters", &clusters_arr);
        dap_json_object_get_ex(obj, "total_count", &total);
        
        if (!clusters_arr || dap_json_get_type(clusters_arr) != DAP_JSON_TYPE_ARRAY) {
            printf("No clusters found\n");
            return 0;
        }
        
        bool l_verbose = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-verbose") != -1;
        int clusters_count = dap_json_array_length(clusters_arr);
        
        printf("\n=== GlobalDB clusters ===\n");
        if (total)
            printf("Total clusters: %"DAP_INT64_FORMAT"\n\n", dap_json_get_int64(total));
        
        for (int i = 0; i < clusters_count; i++) {
            dap_json_t *cluster = dap_json_array_get_idx(clusters_arr, i);
            if (!cluster || dap_json_get_type(cluster) != DAP_JSON_TYPE_OBJECT)
                continue;
            
            dap_json_t *j_mask = NULL, *j_guuid = NULL, *j_mnem = NULL;
            dap_json_t *j_ttl = NULL, *j_role = NULL, *j_root = NULL, *j_links = NULL;
            dap_json_t *j_role_members = NULL, *j_role_members_count = NULL;
            
            dap_json_object_get_ex(cluster, "groups_mask", &j_mask);
            dap_json_object_get_ex(cluster, "links_cluster_guuid", &j_guuid);
            dap_json_object_get_ex(cluster, "mnemonim", &j_mnem);
            dap_json_object_get_ex(cluster, "ttl", &j_ttl);
            dap_json_object_get_ex(cluster, "default_role", &j_role);
            dap_json_object_get_ex(cluster, "owner_root_access", &j_root);
            dap_json_object_get_ex(cluster, "links", &j_links);
            dap_json_object_get_ex(cluster, "role_members", &j_role_members);
            dap_json_object_get_ex(cluster, "role_members_count", &j_role_members_count);
            
            printf("--- Cluster #%d ---\n", i + 1);
            printf("  Groups mask:       %s\n", j_mask ? dap_json_get_string(j_mask) : "N/A");
            printf("  Mnemonim:          %s\n", j_mnem ? dap_json_get_string(j_mnem) : "N/A");
            printf("  Links cluster GUUID: %s\n", j_guuid ? dap_json_get_string(j_guuid) : "N/A");
            printf("  TTL:               %"DAP_UINT64_FORMAT_U" sec\n", j_ttl ? dap_json_get_uint64(j_ttl) : 0);
            printf("  Default role:      %s\n", j_role ? dap_json_get_string(j_role) : "N/A");
            printf("  Owner root access: %s\n", j_root ? (dap_json_get_bool(j_root) ? "Yes" : "No") : "N/A");
            
            // Print role members in verbose mode
            if (l_verbose && j_role_members && dap_json_get_type(j_role_members) == DAP_JSON_TYPE_ARRAY) {
                uint64_t l_members_count = j_role_members_count ? dap_json_get_uint64(j_role_members_count) : 
                                   dap_json_array_length(j_role_members);
                printf("\n  Role members (total: %" DAP_UINT64_FORMAT_U "):\n", l_members_count);
                
                if (l_members_count > 0) {
                    printf("    %-22s | %-10s\n", "Node address", "Role");
                    printf("    %s\n", "--------------------------------------");
                    
                    for (size_t j = 0; j < dap_json_array_length(j_role_members); j++) {
                        dap_json_t *member = dap_json_array_get_idx(j_role_members, j);
                        if (!member || dap_json_get_type(member) != DAP_JSON_TYPE_OBJECT)
                            continue;
                        
                        dap_json_t *j_addr = NULL, *j_member_role = NULL;
                        dap_json_object_get_ex(member, "node_addr", &j_addr);
                        dap_json_object_get_ex(member, "role", &j_member_role);
                        
                        printf("    %-22s | %-10s\n", 
                               j_addr ? dap_json_get_string(j_addr) : "N/A",
                               j_member_role ? dap_json_get_string(j_member_role) : "N/A");
                    }
                } else {
                    printf("    No members\n");
                }
            }

            // Print links in verbose mode
            if (l_verbose && j_links) {
                printf("\n  Links information:\n");
                dap_json_print_object(j_links, stdout, 2);
            }
            
            printf("\n");
        }
        
        return 0;
    }
    
    return 0;
}

