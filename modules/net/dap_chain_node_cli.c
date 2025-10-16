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
#include "dap_notify_srv.h"
#include "dap_json_rpc_response.h"

#define LOG_TAG "chain_node_cli"
static bool s_debug_cli = false;

/*commands for parsing json response*/
static int s_print_for_mempool_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt);
static int s_print_for_srv_stake_all(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt);
static int s_print_for_block_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt);
static int s_print_for_dag_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt);
static int s_print_for_token_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt);
static int s_print_for_srv_xchange_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt);
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
 * @return int
 */
int dap_chain_node_cli_init(dap_config_t * g_config)
{
    if ( !dap_config_get_item_bool_default(g_config, "cli-server", "enabled", true) )
        return log_it( L_WARNING, "CLI server is disabled" ), 0;
    s_debug_cli = dap_config_get_item_bool_default(g_config, "cli-server", "debug-cli", false);
    if ( dap_cli_server_init(s_debug_cli, "cli-server") )
        return log_it(L_ERROR, "Can't init CLI server!"), -1;

    dap_cli_server_cmd_add("global_db", com_global_db, NULL, "Work with global database",
            "global_db flush\n"
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
            "global_db get_keys -group <group_name> [-h]\n"
                "\tGets all record keys from a specified group.\n\n"
            "global_db clear -group <group_name> | -mask <mask> | -all [-pinned]\n"
                "\tRemove all hole type records from a specified group or all groups by mask.\n"
                "\t-mask <mask>: clear groups by mask\n"
                "\t-all: clear all groups\n"
                "\t-pinned: remove pinned records too\n\n"

//                    "global_db wallet_info set -addr <wallet address> -cell <cell id> \n\n"
            );
    dap_cli_server_cmd_add("mempool", com_signer, NULL, "Sign operations",
               "mempool sign -cert <priv_cert_name> -net <net_name> -chain <chain_name> -file <filename> [-mime {<SIGNER_FILENAME,SIGNER_FILENAME_SHORT,SIGNER_FILESIZE,SIGNER_DATE,SIGNER_MIME_MAGIC> | <SIGNER_ALL_FLAGS>}]\n"
               "mempool check -cert <priv_cert_name> -net <net_name> {-file <filename> | -hash <hash>} [-mime {<SIGNER_FILENAME,SIGNER_FILENAME_SHORT,SIGNER_FILESIZE,SIGNER_DATE,SIGNER_MIME_MAGIC> | <SIGNER_ALL_FLAGS>}]\n"
                                          );
    dap_cli_server_cmd_add("node", com_node, NULL, "Work with node",
                    "node add -net <net_name> [-port <port>]\n\n"
                    "node del -net <net_name> {-addr <node_address> | -alias <node_alias>}\n\n"
                    "node link {add | del}  -net <net_name> {-addr <node_address> | -alias <node_alias>} -link <node_address>\n\n"
                    "node alias -addr <node_address> -alias <node_alias>\n\n"
                    "node connect -net <net_name> {-addr <node_address> | -alias <node_alias> | auto}\n\n"
                    "node handshake -net <net_name> {-addr <node_address> | -alias <node_alias>}\n"
                    "node connections [-net <net_name>]\n"
                    "node balancer -net <net_name>\n"
                    "node dump [-net <net_name> | -addr <node_address>]\n\n"
                    "node list -net <net_name> [-addr <node_address> | -alias <node_alias>] [-full]\n\n"
                    "node ban -net <net_name> -certs <certs_name> [-addr <node_address> | -host <ip_v4_or_v6_address>]\n"
                    "node unban -net <net_name> -certs <certs_name> [-addr <node_address> | -host <ip_v4_or_v6_address>]\n"
                    "node banlist\n\n");
    
    dap_cli_server_cmd_add ("version", com_version, NULL, "Return software version",
                                        "version\n"
                                        "\tReturn version number\n"
                                        );

    dap_cli_server_cmd_add ("help", com_help, NULL, "Description of command parameters",
                                        "help [<command>]\n"
                                        "\tObtain help for <command> or get the total list of the commands\n"
                                        );
    dap_cli_server_cmd_add ("?", com_help, NULL, "Synonym for \"help\"",
                                        "? [<command>]\n"
                                        "\tObtain help for <command> or get the total list of the commands\n"
                                        );
    dap_cli_server_cmd_add ("token_update", com_token_update, NULL, "Token update",
                            "\nPrivate or CF20 token update\n"
                            "token_update -net <net_name> [-chain <chain_name>] -token <existing_token_ticker> -type <CF20|private> [-total_supply_change <value>] "
                            "-certs <name_certs> [-flag_set <flag>] [-flag_unset <flag>] [-total_signs_valid <value>] [-description <value>] "
                            "[-tx_receiver_allowed <value>] [-tx_receiver_blocked <value>] [-tx_sender_allowed <value>] [-tx_sender_blocked <value>] "
                            "[-utxo_blocked_add <tx_hash>:<out_idx>[:<timestamp>]] [-utxo_blocked_remove <tx_hash>:<out_idx>[:<timestamp>]] [-utxo_blocked_clear] "
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
                            "\t -total_supply_change <value>:\t\t Sets the maximum amount of token supply. Specify “INF” to set unlimited total supply.\n"
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
                            "\nUTXO blocklist management (for CF20 tokens with UTXO blocking enabled by default):\n"
                            "\t -utxo_blocked_add <tx_hash>:<out_idx>[:<timestamp>]:\n"
                            "\t\t   Blocks specified UTXO. Use <timestamp> for delayed blocking (blockchain time).\n"
                            "\t\t   Format: <tx_hash>:<out_idx> for immediate blocking\n"
                            "\t\t           <tx_hash>:<out_idx>:<timestamp> for delayed activation\n"
                            "\t -utxo_blocked_remove <tx_hash>:<out_idx>[:<timestamp>]:\n"
                            "\t\t   Unblocks specified UTXO. Use <timestamp> for delayed unblocking.\n"
                            "\t\t   Format: <tx_hash>:<out_idx> for immediate removal\n"
                            "\t\t           <tx_hash>:<out_idx>:<timestamp> for scheduled auto-unblock\n"
                            "\t -utxo_blocked_clear:\t\t\t Clears entire UTXO blocklist for this token.\n"
                            "\nNOTE: UTXO blocking flags (use with -flag_set / -flag_unset):\n"
                            "\t UTXO_BLOCKING_DISABLED:\t Disables UTXO blocking mechanism (opt-out).\n"
                            "\t STATIC_UTXO_BLOCKLIST:\t\t Makes UTXO blocklist immutable after first set.\n"
                            "\t DISABLE_ADDRESS_SENDER_BLOCKING:\t Disables tx_send_block/tx_send_allow checks.\n"
                            "\t DISABLE_ADDRESS_RECEIVER_BLOCKING:\t Disables tx_recv_block/tx_recv_allow checks.\n"
                            "\n"
    );
    dap_cli_server_cmd_add ("wallet", com_tx_wallet, NULL, "Wallet operations",
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

    // Token commands
    dap_cli_server_cmd_add ("token_decl", com_token_decl, NULL, "Token declaration",
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
            "\t UTXO_BLOCKING_DISABLED:\t Disables UTXO blocking mechanism (opt-out, blocking enabled by default)\n"
            "\t STATIC_UTXO_BLOCKLIST:\t Makes UTXO blocklist immutable after token creation\n"
            "\t DISABLE_ADDRESS_SENDER_BLOCKING:\t Disables address-based sender blocking (tx_send_block/tx_send_allow ignored)\n"
            "\t DISABLE_ADDRESS_RECEIVER_BLOCKING:\t Disables address-based receiver blocking (tx_recv_block/tx_recv_allow ignored)\n"
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
            "\n"
            );

    dap_cli_server_cmd_add("token_update_sign", com_token_decl_sign, NULL, "Token update add sign to datum",
                                        "token_update_sign -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <cert_list>\n"
                                        "\t Sign existent <datum hash> in mempool with <certs_list>\n"
    );
    // Token commands

    dap_cli_server_cmd_add ("token_decl_sign", com_token_decl_sign, NULL, "Token declaration add sign",
            "token_decl_sign -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <certs_list>\n"
            "\t Sign existent <datum_hash> in mempool with <certs_list>\n"
            );

    dap_cli_server_cmd_add ("token_emit", com_token_emit, NULL, "Token emission",
                            "token_emit { sign -emission <hash> | -token <mempool_token_ticker> -emission_value <value> -addr <addr> } "
                            "[-chain_emission <chain_name>] -net <net_name> -certs <cert_list>\n");

    dap_cli_cmd_t *l_cmd_mempool = dap_cli_server_cmd_add("mempool", com_mempool, NULL, "Command for working with mempool",
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
                                        "Add pubic certificate into the mempool to prepare its way to chains",
            "chain_ca_pub -net <net_name> [-chain <chain_name>] -ca_name <priv_cert_name>\n");

    // Transaction commands
    dap_cli_server_cmd_add ("tx_create", com_tx_create, NULL, "Make transaction",
            "tx_create -net <net_name> [-chain <chain_name>] -value <value> -token <token_ticker> -to_addr <addr> [-lock_before <unlock_time_in_RCF822 or YYMMDD>]"
            "{-from_wallet <wallet_name> | -from_emission <emission_hash> {-cert <cert_name> | -wallet_fee <wallet_name>}} -fee <value>\n");
    dap_cli_server_cmd_add ("tx_create_json", com_tx_create_json, NULL, "Make transaction",
                "tx_create_json -net <net_name> [-chain <chain_name>] -json <json_file_path>\n" );
    dap_cli_server_cmd_add ("mempool_add", com_mempool_add, NULL, "Make transaction and put that to mempool",
                "mempool_add  -net <net_name> [-chain <chain_name>] -json <json_file_path> | -tx_obj <tx_json_object>\n" );
    dap_cli_server_cmd_add ("tx_cond_create", com_tx_cond_create, NULL, "Make cond transaction",
                                        "tx_cond_create -net <net_name> -token <token_ticker> -w <wallet_name>"
                                        " -cert <pub_cert_name> -value <value_datoshi> -fee <value> -unit {B | SEC} -srv_uid <numeric_uid>\n" );
        dap_cli_server_cmd_add ("tx_cond_remove", com_tx_cond_remove, NULL, "Remove cond transactions and return funds from condition outputs to wallet",
                                        "tx_cond_remove -net <net_name> -hashes <hash1,hash2...> -w <wallet_name>"
                                        " -fee <value> -srv_uid <numeric_uid>\n" );
        dap_cli_server_cmd_add ("tx_cond_unspent_find", com_tx_cond_unspent_find, NULL, "Find cond transactions by wallet",
                                        "tx_cond_unspent_find -net <net_name> -srv_uid <numeric_uid> -w <wallet_name> \n" );

    dap_cli_server_cmd_add ("tx_verify", com_tx_verify, NULL, "Verifing transaction in mempool",
            "tx_verify -net <net_name> [-chain <chain_name>] -tx <tx_hash>\n" );

    // Transaction history
    dap_cli_server_cmd_add("tx_history", com_tx_history, NULL, "Transaction history (for address or by hash)",
            "tx_history  {-addr <addr> | {-w <wallet_name> } -net <net_name>} [-chain <chain_name>] [-limit] [-offset] [-head] [-h]\n"
            "tx_history -all -net <net_name> [-chain <chain_name>] [-limit] [-offset] [-head] [-h]\n"
            "tx_history -tx <tx_hash> -net <net_name> [-chain <chain_name>] \n"
            "tx_history -count -net <net_name> [-h]\n");

	// Ledger info
    dap_cli_server_cmd_add("ledger", com_ledger, NULL, "Ledger information",
            "ledger list coins -net <net_name> [-limit] [-offset] [-h]\n"
            "ledger list threshold [-hash <tx_treshold_hash>] -net <net_name> [-limit] [-offset] [-head]\n"
            "ledger list balance -net <net_name> [-limit] [-offset] [-head]\n"
            "ledger info -hash <tx_hash> -net <net_name> [-unspent]\n");

    // Token info
    dap_cli_server_cmd_add("token", com_token, NULL, "Token info",
            "token list -net <net_name> [-full] [-h]\n"
            "\tLists all tokens in specified network. Use -full for detailed information.\n\n"
            "token info -net <net_name> -name <token_ticker> [-h]\n"
            "\tDisplays detailed token information including:\n"
            "\t  - Token properties (ticker, type, supply, decimals)\n"
            "\t  - Flags (including UTXO blocking flags)\n"
            "\t  - Permissions (sender/receiver allow/block lists)\n"
            "\t  - UTXO blocklist (if UTXO blocking is enabled):\n"
            "\t      * tx_hash: Transaction hash of blocked UTXO\n"
            "\t      * out_idx: Output index\n"
            "\t      * blocked_time: When UTXO was added to blocklist\n"
            "\t      * becomes_effective: When blocking activates (delayed activation)\n"
            "\t      * becomes_unblocked: When blocking expires (0 = permanent)\n"
            "\t  - Emission history\n"
            "\t  - Update history\n\n"
            "\tNOTE: UTXO blocklist is displayed only if UTXO_BLOCKING_DISABLED flag is NOT set.\n");

    // Log
    dap_cli_server_cmd_add ("print_log", com_print_log, NULL, "Print log info",
                "print_log [ts_after <timestamp>] [limit <line_numbers>]\n" );

    // Statisticss
    dap_cli_server_cmd_add("stats", com_stats, NULL, "Print statistics",
                "stats cpu");

    // Export GDB to JSON
    dap_cli_server_cmd_add("gdb_export", cmd_gdb_export, NULL, "Export gdb to JSON",
                                        "gdb_export filename <filename without extension> [-groups <group names list>]");

    //Import GDB from JSON
    dap_cli_server_cmd_add("gdb_import", cmd_gdb_import, NULL, "Import gdb from JSON",
                                        "gdb_import filename <filename_without_extension>");

    dap_cli_server_cmd_add ("remove", cmd_remove, NULL, "Delete chain files or global database",
           "remove -gdb\n"
           "remove -chains [-net <net_name> | -all]\n"
                     "Be careful, the '-all' option for '-chains' will delete all chains and won't ask you for permission!");

    // Decree create command
    dap_cli_server_cmd_add ("decree", cmd_decree, NULL, "Work with decree",
            "decree create common -net <net_name> [-chain <chain_name>] -decree_chain <chain_name> -certs <certs_list> {-fee <net_fee_value> -to_addr <net_fee_wallet_addr> | -new_certs <new_owners_certs_list> | -signs_verify <value>}\n"
            "Creates common network decree in net <net_name>. Decree adds to chain -chain and applies to chain -decree_chain. If -chain and -decree_chain is different you must create anchor in -decree_chain that is connected to this decree."
            "\nCommon decree parameters:\n"
            "\t -fee <value>: sets network fee\n"
            "\t -to_addr <wallet_addr>: sets wallet addr for network fee\n"
            "\t -new_certs <certs_list>: sets new owners set for net\n"
            "\t -signs_verify <value>: sets minimum number of owners needed to sign decree\n\n"
            "decree create service -net <net_name> [-chain <chain_name>] -decree_chain <chain_name> -srv_id <service_id> -certs <certs_list> -fee <value> -to_addr <wallet_addr> -new_certs <certs_list> -signs_verify <value>\n"
            "Creates service decree in net <net_name> for service -srv_id.\n\n"
            "decree sign -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <certs_list>\n"
            "Signs decree with hash -datum.\n\n"
            "decree anchor -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <certs_list>\n"
            "Creates anchor for decree with hash -datum.\n\n"
            "decree find -net <net_name> -hash <decree_hash>\n"
            "Find decree by hash and show it's status (apllied or not)\n\n"
            "decree info -net <net_name>\n"
            "Displays information about the parameters of the decrees in the network.\n");

    dap_cli_server_cmd_add ("exec_cmd", com_exec_cmd, NULL, "Execute command on remote node",
            "exec_cmd -net <net_name> -addr <node_addr> -cmd <command,and,all,args,separated,by,commas>\n" );

    //Find command
    dap_cli_server_cmd_add("find", cmd_find, NULL, "The command searches for the specified elements by the specified attributes",
                           "find datum -net <net_name> [-chain <chain_name>] -hash <datum_hash>\n"
                           "\tSearches for datum by hash in the specified network in chains and mempool.\n"
                           "find atom -net <net_name> [-chain <chain_name>] -hash <atom_hash>\n"
                           "\tSearches for an atom by hash in a specified network in chains.\n"
                           "find decree -net <net_name> [-chain <chain_name>] -type <type_decree> [-where <chains|mempool>]\n"
                           "\tSearches for decrees by hash in the specified decree type in the specified network in its chains.\n"
                           "\tTypes decree: fee, owners, owners_min, stake_approve, stake_invalidate, min_value, "
                           "min_validators_count, ban, unban, reward, validator_max_weight, emergency_validators, check_signs_structure\n");


    dap_cli_server_cmd_add ("policy", com_policy, NULL, "Policy commands",
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
    dap_cli_server_cmd_add ("exit", com_exit, NULL, "Stop application and exit",
                "exit\n" );
    dap_notify_srv_set_callback_new(dap_notify_new_client_send_info);
    return 0;
}

int dap_chain_node_cli_parser_init(void) {
    dap_cli_server_cmd_add("block", NULL, s_print_for_block_list, NULL, NULL);    
    dap_cli_server_cmd_add("srv_stake", NULL, s_print_for_srv_stake_all, NULL, NULL);
    dap_cli_server_cmd_add("dag", NULL, s_print_for_dag_list, NULL, NULL);
    dap_cli_server_cmd_add("tx_history", NULL, s_print_for_tx_history_all, NULL, NULL);
    dap_cli_server_cmd_add("token", NULL, s_print_for_token_list, NULL, NULL);
    dap_cli_server_cmd_add("global_db", NULL, s_print_for_global_db, NULL, NULL);
    dap_cli_server_cmd_add("ledger", NULL, s_print_for_ledger_list, NULL, NULL);    
    dap_cli_server_cmd_add("mempool", NULL, s_print_for_mempool_list, NULL, NULL);
    dap_cli_server_cmd_add("srv_xchange", NULL, s_print_for_srv_xchange_list, NULL, NULL);
    
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

int  s_print_for_mempool_list(dap_json_rpc_response_t* response, char **cmd_param, int cmd_cnt){
    dap_return_val_if_pass(!response || !response->result_json_object, -1);
	// Raw JSON flag

	bool l_table_mode = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") != -1;
	if (!l_table_mode) { json_print_object(response->result_json_object, 0); return 0; }
	if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "list") == -1)
		return -2;

	json_object *json_obj_response = json_object_array_get_idx(response->result_json_object, 0);
	if (!json_obj_response)
		return -3;

	json_object *j_obj_net_name = NULL, *j_arr_chains = NULL;
	json_object_object_get_ex(json_obj_response, "net", &j_obj_net_name);
	json_object_object_get_ex(json_obj_response, "chains", &j_arr_chains);
	if (!j_arr_chains || json_object_get_type(j_arr_chains) != json_type_array)
		return -4;

	int chains_count = json_object_array_length(j_arr_chains);
	for (int i = 0; i < chains_count; i++) {
		json_object *json_obj_chain = json_object_array_get_idx(j_arr_chains, i);
		if (!json_obj_chain)
			continue;

		json_object *j_obj_chain_name = NULL, *j_obj_removed = NULL, *j_arr_datums = NULL, *j_obj_total = NULL;
		json_object_object_get_ex(json_obj_chain, "name", &j_obj_chain_name);
		json_object_object_get_ex(json_obj_chain, "removed", &j_obj_removed);
		json_object_object_get_ex(json_obj_chain, "datums", &j_arr_datums);
		json_object_object_get_ex(json_obj_chain, "total", &j_obj_total);

		if (j_obj_removed && j_obj_chain_name && j_obj_net_name) {
			printf("Removed %d records from the %s chain mempool in %s network.\n",
					json_object_get_int(j_obj_removed),
					json_object_get_string(j_obj_chain_name),
					json_object_get_string(j_obj_net_name));
		}

		printf("________________________________________________________________________________________________________________"
            "________________\n");
		printf("  Hash \t\t\t\t\t\t\t\t     | %-22s | %-31s |\n","Datum type", "Time create");

		if (j_arr_datums && json_object_get_type(j_arr_datums) == json_type_array) {
			int datums_count = json_object_array_length(j_arr_datums);
			for (int j = 0; j < datums_count; j++) {
				json_object *j_obj_datum = json_object_array_get_idx(j_arr_datums, j);
				if (!j_obj_datum)
					continue;

				json_object *j_hash = NULL, *j_type = NULL, *j_created = NULL;
				/* hash (v1: "hash", v2: "datum_hash") */
				if (!json_object_object_get_ex(j_obj_datum, "hash", &j_hash))
					json_object_object_get_ex(j_obj_datum, "datum_hash", &j_hash);
				/* type (v1: "type", v2: "datum_type") */
				if (!json_object_object_get_ex(j_obj_datum, "type", &j_type))
					json_object_object_get_ex(j_obj_datum, "datum_type", &j_type);
				/* created object { str, time_stamp } */
				json_object_object_get_ex(j_obj_datum, "created", &j_created);

				const char *hash_str = j_hash ? json_object_get_string(j_hash) : "N/A";
				const char *type_str = j_type ? json_object_get_string(j_type) : "N/A";
				const char *created_str = "N/A";
				char ts_buf[64];
				if (j_created && json_object_get_type(j_created) == json_type_object) {
					json_object *j_created_str = NULL, *j_created_ts = NULL;
					if (json_object_object_get_ex(j_created, "str", &j_created_str) && j_created_str) {
						created_str = json_object_get_string(j_created_str);
					} else if (json_object_object_get_ex(j_created, "time_stamp", &j_created_ts) && j_created_ts) {
						/* print numeric timestamp if readable string is absent */
						snprintf(ts_buf, sizeof(ts_buf), "%"DAP_INT64_FORMAT, json_object_get_int64(j_created_ts));
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
			printf("  total: %s\n", json_object_get_string(j_obj_total));
	}

	return 0;
}
static int s_print_for_srv_stake_list_keys(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    dap_return_val_if_pass(!response || !response->result_json_object, -1);
    // Raw JSON flag
    bool l_table_mode = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") != -1;
    bool l_full = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-full") != -1;

    if (!l_table_mode) { json_print_object(response->result_json_object, 0); return 0; }
    if (json_object_get_type(response->result_json_object) == json_type_array) {
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
        if (l_full) {
            printf("_________________________________________________________________________________________________________________"
                "_________________________"
                   "_________________________________________________________________________________________________________________\n");
            printf(" %-22s| %-69s| %-9s | %-7s | %-10s | %-106s| %-10s |\n",
                   "Node addres", "Pkey hash", "Stake val", "Eff val", "Rel weight", "Sover addr", "Sover tax");
        } else {
            printf("________________________________________________________________________________________________"
                   "_______________________________________________________________________\n");
            printf(" %-22s| %-69s| %-9s | %-7s | %-10s | %-21s | %-10s |\n",
                   "Node addres", "Pkey hash", "Stake val", "Eff val", "Rel weight", "Sover addr", "Sover tax");
        }
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        result_count = json_object_array_length(json_obj_array);
        struct json_object * json_obj_total = NULL;
        for (int i = 0; i < result_count; i++) {
            struct json_object *json_obj_result = json_object_array_get_idx(json_obj_array, i);
            if (!json_obj_result) {
                printf("Failed to get array element at index %d\n", i);
                continue;
            }

            json_object *j_obj_node_addr, *j_obj_pkey_hash, *j_obj_stake_value, *j_obj_effective_value, *j_obj_related_weight,
                   *j_obj_sovereign_addr, *j_obj_sovereign_tax;
            if (json_object_object_get_ex(json_obj_result, "node_addr", &j_obj_node_addr) &&
                json_object_object_get_ex(json_obj_result, "pkey_hash", &j_obj_pkey_hash) &&
                json_object_object_get_ex(json_obj_result, "stake_value", &j_obj_stake_value) &&
                json_object_object_get_ex(json_obj_result, "effective_value", &j_obj_effective_value) &&
                json_object_object_get_ex(json_obj_result, "related_weight", &j_obj_related_weight))
            {
                json_object_object_get_ex(json_obj_result, "sovereign_addr", &j_obj_sovereign_addr);
                json_object_object_get_ex(json_obj_result, "sovereign_tax", &j_obj_sovereign_tax);

                if (j_obj_node_addr && j_obj_pkey_hash && j_obj_stake_value && j_obj_effective_value && j_obj_related_weight
                    && j_obj_sovereign_addr && j_obj_sovereign_tax) {
                    const char *node_addr_full = json_object_get_string(j_obj_node_addr);
                    const char *pkey_hash_full = json_object_get_string(j_obj_pkey_hash);
                    const char *sover_addr_full = json_object_get_string(j_obj_sovereign_addr);
                    int value_coins_width = l_full ? 104 : 20;
                    const char *sovereign_addr_str = (sover_addr_full && strcmp(sover_addr_full, "null")) ?
                                                     (l_full ? sover_addr_full : sover_addr_full + 85) : "------------------- ";
                    printf("%-22s | %-69s|    %4d   |   %4d  |   %4d     | %-*s  |   %-8s |",
                            node_addr_full, pkey_hash_full,
                            json_object_get_int(j_obj_stake_value),
                            json_object_get_int(j_obj_effective_value),
                            json_object_get_int(j_obj_related_weight), 
                            value_coins_width, sovereign_addr_str,
                            json_object_get_string(j_obj_sovereign_tax));
                } else {
                    printf("Missing required fields in array element at index %d\n", i);
                }
            } else {
                json_obj_total = json_obj_result;
                continue;
                //json_print_object(json_obj_result, 0);
            }
            printf("\n");
        }        
        if (!l_full) {
            printf("_______________________|______________________________________________________________________|__"
                   "_________|_________|____________|_______________________|____________|\n\n");
        }
        if (json_obj_total)
            json_print_object(json_obj_total, 0);
    } else {
        json_print_object(response->result_json_object, 0);
    }
    return 0;
}

static int s_print_for_srv_stake_list_tx(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    dap_return_val_if_pass(!response || !response->result_json_object, -1);
    // Raw JSON flag
    bool l_table_mode = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") != -1;
    bool l_full = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-full") != -1;

    if (!l_table_mode) { json_print_object(response->result_json_object, 0); return 0; }
    
    if (json_object_get_type(response->result_json_object) == json_type_array) {
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
        if (l_full) {
            printf("_________________________________________________________________________________________________________________"
                "_________________________________________________________________________________________________________________"
                "____________________________________________________________________________________________________"
                "_________________________________________________________________________________________________________________\n");
            printf(" %-66s | %-31s | %-104s | %-66s | %-22s | %-25s | %-104s |\n", "TX Hash","Date","Signing Addr","Signing Hash","Node Address","Value Coins","Owner Addr");
        } else {
            printf("_________________________________________________________________________________________________________________"
                "________________________________________\n");
            printf(" %-15s | %-31s | %-19s | %-15s | %-22s | %-11s | %-19s |\n", "TX Hash","Date","Signing Addr","Signing Hash","Node Address","Value Coins","Owner Addr");
        }
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        result_count = json_object_array_length(json_obj_array);
        struct json_object * json_obj_total = NULL;
        char hash_buffer[16];
        for (int i = 0; i < result_count; i++) {
            struct json_object *json_obj_result = json_object_array_get_idx(json_obj_array, i);
            if (!json_obj_result) {
                printf("Failed to get array element at index %d\n", i);
                continue;
            }

            json_object *j_obj_tx_hash, *j_obj_date, *j_obj_signing_addr, *j_obj_signing_hash,
                       *j_obj_node_address, *j_obj_value_coins, *j_obj_owner_addr;
            if (json_object_object_get_ex(json_obj_result, "tx_hash", &j_obj_tx_hash) &&
                json_object_object_get_ex(json_obj_result, "date", &j_obj_date) &&
                json_object_object_get_ex(json_obj_result, "signing_addr", &j_obj_signing_addr) &&
                json_object_object_get_ex(json_obj_result, "signing_hash", &j_obj_signing_hash) &&
                json_object_object_get_ex(json_obj_result, "node_address", &j_obj_node_address) &&
                json_object_object_get_ex(json_obj_result, "value_coins", &j_obj_value_coins) &&
                json_object_object_get_ex(json_obj_result, "owner_addr", &j_obj_owner_addr))
            {
                if (j_obj_tx_hash && j_obj_date && j_obj_signing_addr && j_obj_signing_hash && 
                    j_obj_node_address && j_obj_value_coins && j_obj_owner_addr) {
                    
                    // Hash display (full or shortened)
                    const char *full_tx_hash = json_object_get_string(j_obj_tx_hash);
                    const char *tx_hash_short = full_tx_hash;
                    if (!l_full && full_tx_hash && strlen(full_tx_hash) > 15) {
                        strncpy(hash_buffer, full_tx_hash + strlen(full_tx_hash) - 15, 15);
                        hash_buffer[15] = '\0';
                        tx_hash_short = hash_buffer;
                    }
                    
                    // Signing hash display (full or shortened)
                    const char *full_signing_hash = json_object_get_string(j_obj_signing_hash);
                    char signing_hash_buffer[16];
                    const char *signing_hash_short = full_signing_hash;
                    if (!l_full && full_signing_hash && strlen(full_signing_hash) > 15) {
                        strncpy(signing_hash_buffer, full_signing_hash + strlen(full_signing_hash) - 15, 15);
                        signing_hash_buffer[15] = '\0';
                        signing_hash_short = signing_hash_buffer;
                    }
                    
                    // Address display (full or shortened)
                    const char *signing_addr_full = j_obj_signing_addr ? json_object_get_string(j_obj_signing_addr) : NULL;
                    const char *owner_addr_full = j_obj_owner_addr ? json_object_get_string(j_obj_owner_addr) : NULL;
                    const char *node_addr_full = json_object_get_string(j_obj_node_address);
                    const char *signing_addr_str = (signing_addr_full && strcmp(signing_addr_full, "null")) ?
                                                    (l_full ? signing_addr_full : signing_addr_full + 85) : "-------------------";
                    const char *node_addr_str = node_addr_full + 14;
                    const char *owner_addr_str = (owner_addr_full && strcmp(owner_addr_full, "null")) ?
                                                  (l_full ? owner_addr_full : owner_addr_full + 85) : "-------------------";
                    
                    int value_coins_width = l_full ? 25 : 11;
                    const char *value_coins_full = json_object_get_string(j_obj_value_coins);
                    const char *value_coins_str = (value_coins_full && strcmp(value_coins_full, "null"))
                        ? (strlen(value_coins_full) > (size_t)value_coins_width
                            ? value_coins_full + (strlen(value_coins_full) - value_coins_width)
                            : value_coins_full)
                        : "-";

                    printf(" %-15s | %-13s | %-17s | %-14s | %-17s | %-*s | %-17s |\n",
                            tx_hash_short,
                            json_object_get_string(j_obj_date),
                            signing_addr_str,
                            signing_hash_short,
                            node_addr_str,
                            value_coins_width, value_coins_str,
                            owner_addr_str);
                } else {
                    printf("Missing required fields in array element at index %d\n", i);
                }
            } else {
                json_obj_total = json_obj_result;
                continue;
            }
        } 
        if (!l_full) {
            printf("_________________|_________________________________|_____________________|_________________|" 
                      "________________________|_____________|_____________________|\n\n");
        }
        if (json_obj_total)
            json_print_object(json_obj_total, 0);
    } else {
        json_print_object(response->result_json_object, 0);
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
    if (!l_table_mode) { json_print_object(response->result_json_object, 0); return 0; }
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "list") == -1)
        return -2;

    // coins
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "coins") != -1) {
        if (json_object_get_type(response->result_json_object) != json_type_array)
            return -3;

        json_object *root0 = json_object_array_get_idx(response->result_json_object, 0);
        if (!root0)
            return -4;

        // There are two common formats observed:
        // 1) Array of token objects [{...token fields...}, {limit:...}, {offset:...}]
        // 2) Object mapping tickers to token objects { TICKER: {...}, ... }
        // We will detect and handle both. Field names may vary between versions.

        // Case 1: array of objects where each token is an object with field token_name or subtype/supply, etc.
        if (json_object_is_type(root0, json_type_array)) {
            int arr_len = json_object_array_length(root0);
            if (arr_len <= 0) { printf("No coins found\n"); return 0; }

            printf("__________________________________________________________________________________________________________"
                "____________________________\n");
            printf("  %-15s|  %-7s| %-9s|  %-45s|  %-45s|\n",
                   "Token Ticker", "Type", "Decimals", "Total Supply", "Current Supply");
            printf("__________________________________________________________________________________________________________"
                "____________________________\n");

            int printed = 0;
            for (int i = 0; i < arr_len; i++) {
                json_object *it = json_object_array_get_idx(root0, i);
                if (!it || json_object_get_type(it) != json_type_object)
                    continue;

                // Skip control objects like {limit:...} or {offset:...}
                json_object *limit = NULL, *offset = NULL;
                if (json_object_object_get_ex(it, "limit", &limit) || json_object_object_get_ex(it, "offset", &offset))
                    continue;

                const char *ticker = NULL;
                const char *type_str = "N/A";
                const char *supply_total = "N/A";
                const char *supply_current = "N/A";
                int decimals = 0;

                json_object *j_ticker = NULL, *j_type = NULL, *j_dec = NULL, *j_supply_total = NULL, *j_supply_current = NULL;
                // keys vary by version
                if (json_object_object_get_ex(it, "token_name", &j_ticker) ||
                    json_object_object_get_ex(it, "-->Token name", &j_ticker))
                    ticker = json_object_get_string(j_ticker);
                if (json_object_object_get_ex(it, "subtype", &j_type) ||
                    json_object_object_get_ex(it, "type", &j_type))
                    type_str = json_object_get_string(j_type);
                if (json_object_object_get_ex(it, "decimals", &j_dec) ||
                    json_object_object_get_ex(it, "Decimals", &j_dec))
                    decimals = json_object_get_int(j_dec);
                if (json_object_object_get_ex(it, "supply_total", &j_supply_total) ||
                    json_object_object_get_ex(it, "Supply total", &j_supply_total))
                    supply_total = json_object_get_string(j_supply_total);
                if (json_object_object_get_ex(it, "supply_current", &j_supply_current) ||
                    json_object_object_get_ex(it, "Supply current", &j_supply_current))
                    supply_current = json_object_get_string(j_supply_current);

                if (!ticker) {
                    // try to infer ticker from first key if structure is {TICKER:{...}}
                    const char *inferred = NULL;
                    json_object_object_foreach(it, key, val) {
                        if (json_object_is_type(val, json_type_object)) { inferred = key; break; }
                    }
                    ticker = inferred ? inferred : "UNKNOWN";
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
        if (json_object_is_type(root0, json_type_object)) {
            printf("__________________________________________________________________________________________________________\n");
            printf("  %-15s|  %-7s|    %-6s|  %-45s|  %-45s|\n",
                   "Token Ticker", "Type", "Decimals", "Total Supply", "Current Supply");
            printf("__________________________________________________________________________________________________________\n");

            int printed = 0;
            json_object_object_foreach(root0, ticker, token_obj) {
                if (!token_obj || json_object_get_type(token_obj) != json_type_object)
                    continue;
                const char *type_str = "N/A";
                const char *supply_total = "N/A";
                const char *supply_current = "N/A";
                int decimals = 0;

                json_object *j_type = NULL, *j_dec = NULL, *j_supply_total = NULL, *j_supply_current = NULL;
                if (json_object_object_get_ex(token_obj, "subtype", &j_type) ||
                    json_object_object_get_ex(token_obj, "type", &j_type))
                    type_str = json_object_get_string(j_type);
                if (json_object_object_get_ex(token_obj, "decimals", &j_dec) ||
                    json_object_object_get_ex(token_obj, "Decimals", &j_dec))
                    decimals = json_object_get_int(j_dec);
                if (json_object_object_get_ex(token_obj, "supply_total", &j_supply_total) ||
                    json_object_object_get_ex(token_obj, "Supply total", &j_supply_total))
                    supply_total = json_object_get_string(j_supply_total);
                if (json_object_object_get_ex(token_obj, "supply_current", &j_supply_current) ||
                    json_object_object_get_ex(token_obj, "Supply current", &j_supply_current))
                    supply_current = json_object_get_string(j_supply_current);

                printf("  %-15s|  %-7s|    %-6d|  %-45s|  %-45s|\n",
                       ticker, type_str, decimals, supply_total, supply_current);
                printed++;
            }
            if (!printed)
                printf("No coins found\n");
            return 0;
        }

        // Fallback
        json_print_object(response->result_json_object, 0);
        return 0;
    }

    // threshold
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "threshold") != -1) {
        bool l_full = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-full") != -1;
        if (json_object_get_type(response->result_json_object) != json_type_array) {
            json_print_object(response->result_json_object, 0);
            return 0;
        }
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        if (!json_obj_array) {
            printf("Response array is empty\n");
            return -3;
        }
        int result_count = json_object_array_length(json_obj_array);
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
            struct json_object *json_obj_result = json_object_array_get_idx(json_obj_array, i);
            if (!json_obj_result)
                continue;
            // Skip meta objects like {limit}/{offset}
            json_object *j_meta = NULL;
            if (json_object_object_get_ex(json_obj_result, "limit", &j_meta) ||
                json_object_object_get_ex(json_obj_result, "offset", &j_meta))
                continue;

            json_object *j_tx_hash = NULL, *j_time_created = NULL, *j_items_size = NULL;
            // Versioned key for tx hash
            if (!json_object_object_get_ex(json_obj_result, "tx_hash", &j_tx_hash))
                json_object_object_get_ex(json_obj_result, "Ledger thresholded tx_hash_fast", &j_tx_hash);
            json_object_object_get_ex(json_obj_result, "time_created", &j_time_created);
            json_object_object_get_ex(json_obj_result, "tx_item_size", &j_items_size);

            const char *tx_hash_full = j_tx_hash ? json_object_get_string(j_tx_hash) : NULL;
            const char *tx_hash_short = tx_hash_full;
            if (!l_full && tx_hash_full && strlen(tx_hash_full) > 15) {
                strncpy(hash_buffer, tx_hash_full + strlen(tx_hash_full) - 15, 15);
                hash_buffer[15] = '\0';
                tx_hash_short = hash_buffer;
            }
            printf(" %-15s | %-31s | %-12s |\n",
                   l_full ? (tx_hash_full ? tx_hash_full : "-") : (tx_hash_short ? tx_hash_short : "-"),
                   j_time_created ? json_object_get_string(j_time_created) : "-",
                   j_items_size ? json_object_get_string(j_items_size) : "-");
        }
        return 0;
    }

    // balance
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "balance") != -1) {
        bool l_full = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-full") != -1;
        if (json_object_get_type(response->result_json_object) != json_type_array) {
            json_print_object(response->result_json_object, 0);
            return 0;
        }
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        if (!json_obj_array) {
            printf("Response array is empty\n");
            return -3;
        }
        int result_count = json_object_array_length(json_obj_array);
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
            struct json_object *json_obj_result = json_object_array_get_idx(json_obj_array, i);
            if (!json_obj_result)
                continue;
            // Skip meta objects like {limit}/{offset}
            json_object *j_meta = NULL;
            if (json_object_object_get_ex(json_obj_result, "limit", &j_meta) ||
                json_object_object_get_ex(json_obj_result, "offset", &j_meta))
                continue;

            json_object *j_key = NULL, *j_token = NULL, *j_balance = NULL;
            if (!json_object_object_get_ex(json_obj_result, "balance_key", &j_key))
                json_object_object_get_ex(json_obj_result, "Ledger balance key", &j_key);
            json_object_object_get_ex(json_obj_result, "token_ticker", &j_token);
            json_object_object_get_ex(json_obj_result, "balance", &j_balance);
            int key_width = l_full ? 120 : 30;
            const char *key_str_full = j_key ? json_object_get_string(j_key) : "-";            

            printf(" %-*s | %-10s | %-66s |\n",
                   key_width,
                   l_full ? key_str_full : key_str_full+85,
                   j_token ? json_object_get_string(j_token) : "-",
                   j_balance ? json_object_get_string(j_balance) : "-");
        }
        return 0;
    }

    // other ledger list subcmds handled elsewhere or printed raw
    json_print_object(response->result_json_object, 0);
    return 0;
}

static int s_print_for_srv_stake_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    if (!response || !response->result_json_object) {
        printf("Response is empty\n");
        return -1;
    }
    // Full output flag
    bool l_full = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-full") != -1;
    if (json_object_get_type(response->result_json_object) == json_type_array) {
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
        if (l_full) {            
                printf("_________________________________________________________________________________________________________________"
                    "____________________________________________________________________"
                    "__________________________________________________________________________________\n");
                printf(" %-66s | %-13s | %-31s | %-20s | %-11s | %-10s | %-22s | %-66s |\n",
                    "Order", "Direction", "Created", "Price Coins", "Price Token", "Price Unit", "Node Addr", "Pkey");
        } else {
            printf("______________________________________________________________________________"
                "__________________________________________________________________________________\n");
            printf(" %-15s | %-13s | %-31s | %-20s | %-11s | %-10s | %-22s | %-15s |\n",
                   "Order", "Direction", "Created", "Price Coins", "Price Token", "Price Unit", "Node Addr", "Pkey");
        }
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        result_count = json_object_array_length(json_obj_array);
        struct json_object * json_obj_total = NULL;
        char hash_buffer[16];
        for (int i = 0; i < result_count; i++) {
            struct json_object *json_obj_result = json_object_array_get_idx(json_obj_array, i);
            if (!json_obj_result) {
                printf("Failed to get array element at index %d\n", i);
                continue;
            }

            json_object *j_obj_order, *j_obj_direction, *j_obj_created, *j_obj_price_coins,
                       *j_obj_price_token, *j_obj_price_unit, *j_obj_node_addr, *j_obj_pkey;
            if (json_object_object_get_ex(json_obj_result, "order", &j_obj_order) &&
                json_object_object_get_ex(json_obj_result, "direction", &j_obj_direction) &&
                json_object_object_get_ex(json_obj_result, "created", &j_obj_created) &&
                json_object_object_get_ex(json_obj_result, "price coins", &j_obj_price_coins) &&
                json_object_object_get_ex(json_obj_result, "price token", &j_obj_price_token) &&
                json_object_object_get_ex(json_obj_result, "price unit", &j_obj_price_unit) &&
                json_object_object_get_ex(json_obj_result, "node_addr", &j_obj_node_addr) &&
                json_object_object_get_ex(json_obj_result, "pkey", &j_obj_pkey))
            {
                if (j_obj_order && j_obj_direction && j_obj_created && j_obj_price_coins && 
                    j_obj_price_token && j_obj_price_unit && j_obj_node_addr && j_obj_pkey) {
                    
                    // Order hash display (full or shortened)
                    const char *full_order = json_object_get_string(j_obj_order);
                    const char *order_short = full_order;
                    if (!l_full && full_order && strlen(full_order) > 15) {
                        strncpy(hash_buffer, full_order + strlen(full_order) - 15, 15);
                        hash_buffer[15] = '\0';
                        order_short = hash_buffer;
                    }
                    
                    // pkey display (full or shortened)
                    const char *full_pkey = json_object_get_string(j_obj_pkey);
                    char pkey_buffer[16];
                    const char *pkey_short = full_pkey;
                    if (!l_full && full_pkey && strlen(full_pkey) > 15) {
                        strncpy(pkey_buffer, full_pkey + strlen(full_pkey) - 15, 15);
                        pkey_buffer[15] = '\0';
                        pkey_short = pkey_buffer;
                    }
                    
                    // Shortened node address display (starting from position 85, like in xchange)
                    const char *node_addr_str = json_object_get_string(j_obj_node_addr);
                    
                    printf(" %-15s | %-13s | %-17s | %-20s | %-11s | %-10s | %-13s | %-15s |\n",
                            order_short,
                            json_object_get_string(j_obj_direction),
                            json_object_get_string(j_obj_created),
                            json_object_get_string(j_obj_price_coins),
                            json_object_get_string(j_obj_price_token),
                            json_object_get_string(j_obj_price_unit),
                            node_addr_str,
                            pkey_short);
                } else {
                    printf("Missing required fields in array element at index %d\n", i);
                }
            } else {
                json_obj_total = json_obj_result;
                continue;
            }
        }
        if (json_obj_total)
            json_print_object(json_obj_total, 0);
    } else {
        json_print_object(response->result_json_object, 0);
    }
    return 0;
}

static int s_print_for_srv_stake_all(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    // Raw JSON flag
    bool table_mode_all = false; 
    for (int i = 0; i < cmd_cnt; i++) { 
        const char *p = cmd_param[i]; 
        if (!p) continue; 
        if (!strcmp(p, "-h")) { 
            table_mode_all = true; break; 
        } 
    }
    if (!table_mode_all) { 
        // If no specific handler found, use default output
        if (response && response->result_json_object) {
            json_print_object(response->result_json_object, 0);
            return 0;
        }
    }
    // Check for different srv_stake subcommands
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "list") != -1) {
        if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "keys") != -1) {
            return s_print_for_srv_stake_list_keys(response, cmd_param, cmd_cnt);
        } else if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "tx") != -1) {
            return s_print_for_srv_stake_list_tx(response, cmd_param, cmd_cnt);
        } else if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "order") != -1) {
            return s_print_for_srv_stake_list(response, cmd_param, cmd_cnt);
        }
    }    
    
    
    printf("Unknown srv_stake subcommand or response is empty\n");
    return -1;
}

static int s_print_for_block_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    
    dap_return_val_if_pass(!response || !response->result_json_object, -1);

    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") == -1) {
        json_print_object(response->result_json_object, 0);
        return 0;
    }
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "list") == -1)
        return -2;
    if (json_object_get_type(response->result_json_object) == json_type_array) {
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 1) {
            printf("Response array is empty\n");
            return -3;
        }
        printf("_________________________________________________________________________________________________________________\n");
        printf("  Block # | Block hash \t\t\t\t\t\t\t       | Time create \t\t\t | \n");
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        result_count = json_object_array_length(json_obj_array);
        char *l_limit = NULL;
        char *l_offset = NULL;
        for (int i = 0; i < result_count; i++) {
            struct json_object *json_obj_result = json_object_array_get_idx(json_obj_array, i);
            if (!json_obj_result) {
                printf("Failed to get array element at index %d\n", i);
                continue;
            }

            json_object *j_obj_block_number, *j_obj_hash, *j_obj_create, *j_obj_lim, *j_obj_off;
            if (json_object_object_get_ex(json_obj_result, "block number", &j_obj_block_number) &&
                json_object_object_get_ex(json_obj_result, "hash", &j_obj_hash) &&
                json_object_object_get_ex(json_obj_result, "ts_create", &j_obj_create))
            {
                if (j_obj_block_number && j_obj_hash && j_obj_create) {
                    printf("   %5s  | %s | %s |",
                            json_object_get_string(j_obj_block_number), json_object_get_string(j_obj_hash), json_object_get_string(j_obj_create));
                } else {
                    printf("Missing required fields in array element at index %d\n", i);
                }
            } else if (json_object_object_get_ex(json_obj_result, "limit", &j_obj_lim)) {
                json_object_object_get_ex(json_obj_result, "offset", &j_obj_off);
                l_limit = json_object_get_int64(j_obj_lim) ? dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_lim)) : dap_strdup_printf("unlimit");
                if (j_obj_off)
                    l_offset = dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_off));
                continue;
            } else {
                json_print_object(json_obj_result, 0);
            }
            printf("\n");
        }
        printf("__________|____________________________________________________________________|_________________________________|\n\n");
        if (l_limit) {            
            printf("\tlimit: %s \n", l_limit);
            DAP_DELETE(l_limit);
        }
        if (l_offset) {            
            printf("\toffset: %s \n", l_offset);
            DAP_DELETE(l_offset);
        }
    } else {
        //json_print_object(response->result_json_object, 0);
        return -4;
    }
    return 0;
}

static int s_print_for_dag_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){

    dap_return_val_if_pass(!response || !response->result_json_object, -1);
    // Raw JSON flag
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") == -1) {
        json_print_object(response->result_json_object, 0);
        return 0;
    }
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "list") == -1)
        return -2;
    if (json_object_get_type(response->result_json_object) == json_type_array) {
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
        printf("________________________________________________________________________________________________________________\n");
        printf(" %7s | Hash \t\t\t\t\t\t\t      | Time create \t\t        |\n","#");
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        struct json_object *j_object_events = NULL;
        char *l_limit = NULL;
        char *l_offset = NULL;
        
        if (json_object_object_get_ex(json_obj_array, "events", &j_object_events) || json_object_object_get_ex(json_obj_array, "EVENTS", &j_object_events)
           || json_object_object_get_ex(json_obj_array, "TRESHOLD", &j_object_events) || json_object_object_get_ex(json_obj_array, "treshold", &j_object_events))
        {
            result_count = json_object_array_length(j_object_events);
            for (int i = 0; i < result_count; i++) {
                struct json_object *json_obj_result = json_object_array_get_idx(j_object_events, i);
                if (!json_obj_result) {
                    printf("Failed to get array element at index %d\n", i);
                    continue;
                }

                json_object *j_obj_event_number, *j_obj_hash, *j_obj_create, *j_obj_lim, *j_obj_off;
                if (json_object_object_get_ex(json_obj_result, "event number", &j_obj_event_number) &&
                    json_object_object_get_ex(json_obj_result, "hash", &j_obj_hash) &&
                    json_object_object_get_ex(json_obj_result, "ts_create", &j_obj_create))
                {
                    if (j_obj_event_number && j_obj_hash && j_obj_create) {
                        printf(" %7s | %s | %s\t|",
                                json_object_get_string(j_obj_event_number), json_object_get_string(j_obj_hash), json_object_get_string(j_obj_create));
                    } else {
                        printf("Missing required fields in array element at index %d\n", i);
                    }
                } else if (json_object_object_get_ex(json_obj_result, "limit", &j_obj_lim)) {
                    json_object_object_get_ex(json_obj_result, "offset", &j_obj_off);
                    l_limit = json_object_get_int64(j_obj_lim) ? dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_lim)) : dap_strdup_printf("unlimit");
                    if (j_obj_off)
                        l_offset = dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_off));
                    continue;
                } else {
                    json_print_object(json_obj_result, 0);
                }             
                printf("\n");
            }
            printf("_________|____________________________________________________________________|_________________________________|\n\n");
        } else {
            printf("EVENTS is empty\n");
            return -4;
        }
        if (l_limit) {            
            printf("\tlimit: %s \n", l_limit);
            DAP_DELETE(l_limit);
        } 
        if (l_offset) {            
            printf("\toffset: %s \n", l_offset);
            DAP_DELETE(l_offset);
        }           
    } else {
        json_print_object(response->result_json_object, 0);
        return -5;
    }
    return 0;

}

static int s_print_for_token_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    if (!response || !response->result_json_object) {
        printf("Response is empty\n");
        return -1;
    }
    bool l_table_mode = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") != -1;
    bool l_full = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-full") != -1;

    if (!l_table_mode) { json_print_object(response->result_json_object, 0); return 0; }

    
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "list") == -1)
        return -2;
    
    if (json_object_get_type(response->result_json_object) == json_type_array) {        
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
                
        struct json_object *json_obj_main = json_object_array_get_idx(response->result_json_object, 0);
        struct json_object *j_object_tokens = NULL;
        
        // Get TOKENS or tokens array
        if (!json_object_object_get_ex(json_obj_main, "TOKENS", &j_object_tokens) &&
            !json_object_object_get_ex(json_obj_main, "tokens", &j_object_tokens)) {
            printf("TOKENS field not found\n");
            return -4;
        }
        
        int chains_count = json_object_array_length(j_object_tokens);
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
        
        // Iterate through chains
        for (int chain_idx = 0; chain_idx < chains_count; chain_idx++) {
            struct json_object *chain_tokens = json_object_array_get_idx(j_object_tokens, chain_idx);
            if (!chain_tokens)
                continue;
                
            // Iterate through tokens in this chain
            json_object_object_foreach(chain_tokens, ticker, token_obj) {
                total_tokens++;
                
                struct json_object *current_state = NULL;
                struct json_object *declarations = NULL;
                struct json_object *updates = NULL;
                
                json_object_object_get_ex(token_obj, "current_state", &current_state);
                json_object_object_get_ex(token_obj, "current state", &current_state);
                json_object_object_get_ex(token_obj, "declarations", &declarations);
                json_object_object_get_ex(token_obj, "updates", &updates);
                
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
                    struct json_object *total_supply_obj = NULL;
                    struct json_object *current_supply_obj = NULL;
                    struct json_object *type_obj = NULL;
                    struct json_object *signs_obj = NULL;
                    struct json_object *decimals_obj = NULL;
                    
                    if (json_object_object_get_ex(current_state, "Supply total", &total_supply_obj))
                        total_supply = json_object_get_string(total_supply_obj);
                    if (json_object_object_get_ex(current_state, "Supply current", &current_supply_obj))
                        current_supply = json_object_get_string(current_supply_obj);
                    if (json_object_object_get_ex(current_state, "type", &type_obj))
                        token_type = json_object_get_string(type_obj);
                    if (json_object_object_get_ex(current_state, "Auth signs valid", &signs_obj))
                        current_signs = json_object_get_string(signs_obj);
                    if (json_object_object_get_ex(current_state, "Decimals", &decimals_obj))
                        decimals = json_object_get_int(decimals_obj);
                }
                
                // Extract declaration info (get latest declaration)
                if (declarations && json_object_array_length(declarations) > 0) {
                    struct json_object *latest_decl = json_object_array_get_idx(declarations, 
                        json_object_array_length(declarations) - 1);
                    if (latest_decl) {
                        struct json_object *status_obj = NULL;
                        struct json_object *hash_obj = NULL;
                        
                        if (json_object_object_get_ex(latest_decl, "status", &status_obj))
                            decl_status = json_object_get_string(status_obj);
                        
                        struct json_object *datum_obj = NULL;
                        if (json_object_object_get_ex(latest_decl, "Datum", &datum_obj)) {
                            if (json_object_object_get_ex(datum_obj, "hash", &hash_obj)) {
                                const char *full_hash = json_object_get_string(hash_obj);
                                decl_hash_short = full_hash;
                                if (!l_full && full_hash && strlen(full_hash) > 10) {
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
                
                int decl_count = declarations ? json_object_array_length(declarations) : 0;
                int upd_count = updates ? json_object_array_length(updates) : 0;
                
                printf("  %-15s|  %-7s|    %-6d|     %-10s|      %-9d|   %-7d|   %-9s|  %-*s|  %-40s|  %-40s|\n",
                    ticker,
                    token_type,
                    decimals,
                    current_signs,
                    decl_count,
                    upd_count,
                    decl_status,
                    strlen(decl_hash_short)+1,
                    decl_hash_short,
                    total_supply,
                    current_supply
                );
            }
        }
        
        printf("\nTotal tokens: %d\n", total_tokens);
        
        // Show tokens_count if available
        struct json_object *tokens_count_obj = NULL;
        if (json_object_object_get_ex(json_obj_main, "tokens_count", &tokens_count_obj)) {
            printf("Tokens count: %s\n", json_object_get_string(tokens_count_obj));
        }
        
    } else {
        json_print_object(response->result_json_object, 0);
        return -6;
    }
    return 0;
}


static int s_print_for_srv_xchange_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    dap_return_val_if_pass(!response || !response->result_json_object, -1);
    // Raw JSON flag
    bool l_table_mode = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-h") != -1;
    bool l_full = dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-full") != -1;
    
    if (!l_table_mode) { json_print_object(response->result_json_object, 0); return 0; }
    struct json_object *j_obj_headr = NULL, *limit_obj = NULL, *l_arr_pages = NULL, *l_obj_pages = NULL,
			*offset_obj = NULL, *l_arr_orders = NULL;
	char *l_limit = NULL;
	char *l_offset = NULL;
	size_t l_print_count = 0;

	// Common header for pagination (mainly for 'orders')
	j_obj_headr = json_object_array_get_idx(response->result_json_object, 0);
	if (j_obj_headr) {
		if (json_object_object_get_ex(j_obj_headr, "pages", &l_arr_pages) && l_arr_pages) {
			l_obj_pages = json_object_array_get_idx(l_arr_pages, 0);
			if (l_obj_pages) {
				json_object_object_get_ex(l_obj_pages, "limit", &limit_obj);
				json_object_object_get_ex(l_obj_pages, "offset", &offset_obj);
				if (limit_obj)
					l_limit = json_object_get_int64(limit_obj) ? dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(limit_obj)) : dap_strdup_printf("unlimit");
				if (offset_obj)
					l_offset = json_object_get_int64(offset_obj) ? dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(offset_obj)) : NULL;
			}
		}
		if(!json_object_object_get_ex(j_obj_headr, "orders", &l_arr_orders) &&
			!json_object_object_get_ex(j_obj_headr, "ORDERS", &l_arr_orders)&&
			!json_object_object_get_ex(j_obj_headr, "TICKERS PAIR", &l_arr_orders) &&
			dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "tx_list") == -1) {
			return -2;
		}
	}

	// Branch: orders
	if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "orders") != -1) {
		if (json_object_get_type(response->result_json_object) == json_type_array && l_arr_orders) {
			int result_count = json_object_array_length(l_arr_orders);
			if (result_count <= 0) {
				printf("Response array is empty\n");
				return -3;
			}
            if (l_full) {
			    printf("______________________________________________________________________________________________"
			    	"_________________________________________________________________________________________________________"
			    	"_________________________________________________________________________________________________________\n");
			    printf("   %-67s | %-31s | %s | %-22s | %-22s | %3s | %-10s | %-10s | %-22s | %-104s |\n",
			    		"Order hash", "Time create", "Status",
			    		"Proposed coins","Amount coins","%",
			    		"Token buy", "Token sell","Rate", "Owner addr");
            } else {
                printf("_____________________________________________________________________________________________"
			    	"____________________________________________________________________________________________________\n");
			    printf("   %-16s | %-31s | %s | %-22s | %-22s | %3s | %-10s | %-10s | %-22s | %-19s |\n",
			    		"Order hash", "Time create", "Status",
			    		"Proposed coins","Amount coins","%",
			    		"Token buy", "Token sell","Rate", "Owner addr");
            }
			for (int i = 0; i < result_count; i++) {
				struct json_object *json_obj_result = json_object_array_get_idx(l_arr_orders, i);
				json_object *j_obj_status = NULL, *j_obj_hash = NULL, *j_obj_create = NULL, *j_obj_prop_coin = NULL,
					*j_obj_amount_coin = NULL, *j_obj_filed_perc = NULL, *j_obj_token_buy = NULL, *j_obj_token_sell = NULL, *j_obj_rate = NULL, *j_obj_owner_addr = NULL;
				if (json_object_object_get_ex(json_obj_result, "order_hash", &j_obj_hash) &&
					json_object_object_get_ex(json_obj_result, "ts_created", &j_obj_create) &&
					json_object_object_get_ex(json_obj_result, "status", &j_obj_status) &&
					json_object_object_get_ex(json_obj_result, "proposed_coins", &j_obj_prop_coin) &&
					json_object_object_get_ex(json_obj_result, "amount_coins", &j_obj_amount_coin) &&
					json_object_object_get_ex(json_obj_result, "filled_percent", &j_obj_filed_perc) &&
					json_object_object_get_ex(json_obj_result, "token_buy", &j_obj_token_buy) &&
					json_object_object_get_ex(json_obj_result, "token_sell", &j_obj_token_sell) &&
					json_object_object_get_ex(json_obj_result, "rate", &j_obj_rate) &&
					json_object_object_get_ex(json_obj_result, "owner_addr", &j_obj_owner_addr)) {
					const char *full_hash = json_object_get_string(j_obj_hash);
					char hash_buffer[16];
					const char *hash_print = full_hash;
					if (!l_full && full_hash && strlen(full_hash) > 15) {
						strncpy(hash_buffer, full_hash + strlen(full_hash) - 15, 15);
						hash_buffer[15] = '\0';
						hash_print = hash_buffer;
					}
					/* Prepare 22-char fixed-width prints (always take last 22 chars) */
					const char *prop_full = json_object_get_string(j_obj_prop_coin);
					const char *amount_full = json_object_get_string(j_obj_amount_coin);
					const char *rate_full = json_object_get_string(j_obj_rate);
					const char *owner_addr_full = j_obj_owner_addr ? json_object_get_string(j_obj_owner_addr) : NULL;
					char prop_buf[23];
					char amount_buf[23];
					char rate_buf[23];
					const char *prop_print = prop_full ? prop_full : "-";
					const char *amount_print = amount_full ? amount_full : "-";
					const char *rate_print = rate_full ? rate_full : "-";
					const char *owner_addr_print = (owner_addr_full && strcmp(owner_addr_full, "null")) ? (l_full ? owner_addr_full : owner_addr_full + 85) : "-------------------";
					if (prop_print && strlen(prop_print) > 22) { strncpy(prop_buf, prop_print + strlen(prop_print) - 22, 22); prop_buf[22] = '\0'; prop_print = prop_buf; }
					if (amount_print && strlen(amount_print) > 22) { strncpy(amount_buf, amount_print + strlen(amount_print) - 22, 22); amount_buf[22] = '\0'; amount_print = amount_buf; }
					if (rate_print && strlen(rate_print) > 22) { strncpy(rate_buf, rate_print + strlen(rate_print) - 22, 22); rate_buf[22] = '\0'; rate_print = rate_buf; }
					printf("   %s  | %s | %s | %-22s | %-22s | %3d | %-10s | %-10s | %-22s | %-s |\n",
						hash_print, json_object_get_string(j_obj_create), json_object_get_string(j_obj_status),
						prop_print, amount_print, (int)json_object_get_uint64(j_obj_filed_perc),
						json_object_get_string(j_obj_token_buy), json_object_get_string(j_obj_token_sell), rate_print, owner_addr_print);
					l_print_count++;
				}
			}

			if (l_limit) { printf("\tlimit: %s \n", l_limit); DAP_DELETE(l_limit); }
			if (l_offset) { printf("\toffset: %s \n", l_offset); DAP_DELETE(l_offset); }
			printf("\torders printed: %zd\n", l_print_count);
		} else {
			return -4;
		}
		return 0;
	}

	// Branch: token_pair
	if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "token_pair") != -1) {
		// list all
		if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "list") != -1) {
			struct json_object *l_obj_pairs = NULL, *l_pairs_arr = NULL, *l_pair_cnt = NULL;
			int top_len = json_object_array_length(response->result_json_object);
			for (int i = 0; i < top_len; i++) {
				struct json_object *el = json_object_array_get_idx(response->result_json_object, i);
				if (el && json_object_get_type(el) == json_type_object) {
					if (json_object_object_get_ex(el, "tickers_pair", &l_pairs_arr) ||
						json_object_object_get_ex(el, "TICKERS PAIR", &l_pairs_arr)) { l_obj_pairs = el; break; }
				}
			}
            if (!l_obj_pairs || !l_pairs_arr || json_object_get_type(l_pairs_arr) != json_type_array) return -5;
			printf("______________________________\n");
			printf(" %-10s | %-10s |\n", "Ticker 1", "Ticker 2");
            for (size_t i = 0; i < (size_t)json_object_array_length(l_pairs_arr); i++) {
				struct json_object *pair = json_object_array_get_idx(l_pairs_arr, i);
				struct json_object *t1 = NULL, *t2 = NULL;
				json_object_object_get_ex(pair, "ticker_1", &t1);
				json_object_object_get_ex(pair, "ticker_2", &t2);
				if (t1 && t2) printf(" %-10s | %-10s |\n", json_object_get_string(t1), json_object_get_string(t2));
			}
            if (json_object_object_get_ex(l_obj_pairs, "pair_count", &l_pair_cnt) || json_object_object_get_ex(l_obj_pairs, "pair count", &l_pair_cnt))
                printf("\nTotal pairs: %"DAP_INT64_FORMAT"\n", json_object_get_int64(l_pair_cnt));
			return 0;
		}
		// rate average
		if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "average") != -1) {
			int top_len = json_object_array_length(response->result_json_object);
			for (int i = 0; i < top_len; i++) {
				struct json_object *el = json_object_array_get_idx(response->result_json_object, i);
				if (el && json_object_get_type(el) == json_type_object) {
					struct json_object *avg = NULL, *last = NULL, *last_ts = NULL;
					if (json_object_object_get_ex(el, "average_rate", &avg) || json_object_object_get_ex(el, "Average rate", &avg)) {
						json_object_object_get_ex(el, "last_rate", &last); json_object_object_get_ex(el, "Last rate", &last);
						json_object_object_get_ex(el, "last_rate_time", &last_ts); json_object_object_get_ex(el, "Last rate time", &last_ts);
						printf("Average rate: %s\n", json_object_get_string(avg));
						if (last) printf("Last rate: %s\n", json_object_get_string(last));
						if (last_ts) printf("Last rate time: %s\n", json_object_get_string(last_ts));
						return 0;
					}
				}
			}
			return -6;
		}
		// rate history
		if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "history") != -1) {
			struct json_object *l_arr = NULL;
			struct json_object *l_summary = NULL;
			int top_len = json_object_array_length(response->result_json_object);
			for (int i = 0; i < top_len; i++) {
				struct json_object *el = json_object_array_get_idx(response->result_json_object, i);
				if (el && json_object_get_type(el) == json_type_array && !l_arr) l_arr = el;
				if (el && json_object_get_type(el) == json_type_object) l_summary = el;
			}
			if (!l_arr) return -7;
			printf("__________________________________________________________________________________________________\n");
			printf(" Hash | Action | Token | Time create\n");
			printf("__________________________________________________________________________________________________\n");
            for (size_t i = 0; i < (size_t)json_object_array_length(l_arr); i++) {
				struct json_object *it = json_object_array_get_idx(l_arr, i);
				struct json_object *hash = NULL, *action = NULL, *token = NULL, *ts = NULL;
				json_object_object_get_ex(it, "hash", &hash);
				json_object_object_get_ex(it, "action", &action);
				json_object_object_get_ex(it, "token ticker", &token);
				json_object_object_get_ex(it, "tx created", &ts);
				if (hash && action && token && ts)
					printf(" %s | %s | %s | %s\n", json_object_get_string(hash), json_object_get_string(action), json_object_get_string(token), json_object_get_string(ts));
				else
					json_print_object(it, 1);
			}
			if (l_summary) {
				struct json_object *tx_cnt = NULL;
				struct json_object *v1_from = NULL, *v1_to = NULL, *v2_from = NULL, *v2_to = NULL;
				json_object_object_get_ex(l_summary, "tx_count", &tx_cnt);
                if (tx_cnt) printf("\nTotal transactions: %"DAP_INT64_FORMAT"\n", json_object_get_int64(tx_cnt));
				if (json_object_object_get_ex(l_summary, "trading_val_from_coins", &v1_from) || json_object_object_get_ex(l_summary, "trading_val_from_datoshi", &v2_from) ||
					json_object_object_get_ex(l_summary, "trading_val_to_coins", &v1_to) || json_object_object_get_ex(l_summary, "trading_val_to_datoshi", &v2_to)) {
					printf("Trading from: %s (%s)\n", v1_from ? json_object_get_string(v1_from) : "-", v2_from ? json_object_get_string(v2_from) : "-");
					printf("Trading to:   %s (%s)\n", v1_to ? json_object_get_string(v1_to) : "-", v2_to ? json_object_get_string(v2_to) : "-");
				}
			}
			return 0;
		}
		return -8;
	}

	// Branch: tx_list
	if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "tx_list") != -1) {
		struct json_object *l_arr = NULL, *l_total = NULL;
		int top_len = json_object_array_length(response->result_json_object);
		for (int i = 0; i < top_len; i++) {
			struct json_object *el = json_object_array_get_idx(response->result_json_object, i);
			if (!el) continue;
			if (!l_arr && json_object_get_type(el) == json_type_array) l_arr = el;
			else if (json_object_get_type(el) == json_type_object) l_total = el;
		}
		if (!l_arr) return -9;
        char hash_buffer[16];
		printf("__________________________________________________________________________________________________\n");
		printf(" Hash \t\t | Status    | Token      | Time create \t\t    | Owner \t      | Buyer\n");
        for (size_t i = 0; i < (size_t)json_object_array_length(l_arr); i++) {
			struct json_object *it = json_object_array_get_idx(l_arr, i);
			struct json_object *hash = NULL, *status = NULL, *token = NULL, *ts = NULL, *owner_addr = NULL, *buyer_addr = NULL;
			json_object_object_get_ex(it, "hash", &hash);
			json_object_object_get_ex(it, "status", &status);
			json_object_object_get_ex(it, "ticker", &token);
			json_object_object_get_ex(it, "ts_created", &ts);
			json_object_object_get_ex(it, "owner_addr", &owner_addr);
			json_object_object_get_ex(it, "buyer_addr", &buyer_addr);
			const char * owner_addr_full = owner_addr ? json_object_get_string(owner_addr) : NULL;
			const char * buyer_addr_full = buyer_addr ? json_object_get_string(buyer_addr) : NULL;
			char owner_short[32] = {0}, buyer_short[32] = {0};
			const char * owner_addr_str = "-------------------";
			const char * buyer_addr_str = "-------------------";
			if (owner_addr_full && strcmp(owner_addr_full, "null")) {
				if (!l_full && strlen(owner_addr_full) > 15) {
					strncpy(owner_short, owner_addr_full + strlen(owner_addr_full) - 15, 15);
					owner_short[15] = '\0';
					owner_addr_str = owner_short;
				} else {
					owner_addr_str = owner_addr_full;
				}
			}
			if (buyer_addr_full && strcmp(buyer_addr_full, "null")) {
				if (!l_full && strlen(buyer_addr_full) > 15) {
					strncpy(buyer_short, buyer_addr_full + strlen(buyer_addr_full) - 15, 15);
					buyer_short[15] = '\0';
					buyer_addr_str = buyer_short;
				} else {
					buyer_addr_str = buyer_addr_full;
				}
			}
			if (hash && token && ts && status) {
				const char *full_hash = json_object_get_string(hash);
				char hash_buffer2[16];
				const char *hash_print = full_hash;
				if (!l_full && full_hash && strlen(full_hash) > 15) {
					strncpy(hash_buffer2, full_hash + strlen(full_hash) - 15, 15);
					hash_buffer2[15] = '\0';
					hash_print = hash_buffer2;
				}
				printf(" %-15s | %-9s | %-10s | %s | %s | %s\n", hash_print, json_object_get_string(status), json_object_get_string(token), json_object_get_string(ts), owner_addr_str, buyer_addr_str);
			} else {
				json_print_object(it, 1);
			}
		}
		if (l_total) {
			struct json_object *cnt = NULL;
			json_object_object_get_ex(l_total, "total_tx_count", &cnt);
			if (!cnt) json_object_object_get_ex(l_total, "number of transactions", &cnt);
            if (cnt) printf("\nTotal transactions: %"DAP_INT64_FORMAT"\n", json_object_get_int64(cnt));
		}
		return 0;
	}

	return -10;
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
    if (!l_table_mode) { json_print_object(response->result_json_object, 0); return 0; }
	if (json_object_get_type(response->result_json_object) == json_type_array) {
		int result_count = json_object_array_length(response->result_json_object);
		if (result_count <= 0) {
			printf("Response array is empty\n");
			return -2;
		}

		// Special handling for -addr and -w: array[0] is tx list with address header, array[1] is summary
		if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-addr") != -1 ||
			dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "-w") != -1) {
			json_object *tx_array = json_object_array_get_idx(response->result_json_object, 0);
			json_object *summary_obj = json_object_array_get_idx(response->result_json_object, 1);
			if (tx_array && json_object_get_type(tx_array) == json_type_array) {
				// Print address header if present as the first element
				json_object *first_el = json_object_array_get_idx(tx_array, 0);
				json_object *addr_obj = NULL;
				if (first_el && json_object_get_type(first_el) == json_type_object &&
				   (json_object_object_get_ex(first_el, "addr", &addr_obj) ||
				    json_object_object_get_ex(first_el, "address", &addr_obj))) {
					printf("Address: %s\n", json_object_get_string(addr_obj));
				}

				printf("_________________________________________________________________________________________________________________"
					"________________________________________________\n");
				printf(" # \t| Hash \t\t\t\t\t\t\t\t     | Status   | Action \t  | Service \t     | Time create\n");
				printf("_________________________________________________________________________________________________________________"
					"________________________________________________\n");

				char *l_limit = NULL; char *l_offset = NULL; int row_num = 0;
				for (size_t i = 0; i < (size_t)json_object_array_length(tx_array); i++) {
					json_object *tx_obj = json_object_array_get_idx(tx_array, (int)i);
					if (!tx_obj || json_object_get_type(tx_obj) != json_type_object)
						continue;
					// Skip header element with addr/address
					json_object *tmp = NULL;
					if (json_object_object_get_ex(tx_obj, "addr", &tmp) || json_object_object_get_ex(tx_obj, "address", &tmp)){
						continue;
					}
					// Handle limit/offset info
					json_object *j_obj_lim = NULL, *j_obj_off = NULL;
					if (json_object_object_get_ex(tx_obj, "limit", &j_obj_lim)) {
						json_object_object_get_ex(tx_obj, "offset", &j_obj_off);
						l_limit = json_object_get_int64(j_obj_lim) ? dap_strdup_printf("%"DAP_INT64_FORMAT, json_object_get_int64(j_obj_lim)) : dap_strdup_printf("unlimit");
						if (j_obj_off)
							l_offset = dap_strdup_printf("%"DAP_INT64_FORMAT, json_object_get_int64(j_obj_off));
						continue;
					}

					json_object *hash_obj = NULL, *status_obj = NULL, *action_obj = NULL, *service_obj = NULL, *created_obj = NULL;
					if (json_object_object_get_ex(tx_obj, "hash", &hash_obj) &&
						json_object_object_get_ex(tx_obj, "status", &status_obj) &&
						json_object_object_get_ex(tx_obj, "action", &action_obj) &&
						json_object_object_get_ex(tx_obj, "service", &service_obj) &&
						json_object_object_get_ex(tx_obj, "tx_created", &created_obj)) {
						row_num++;
						printf("%d\t| %-60s | %s\t| %-15s |  %-16s| %s\t|\n",
							row_num,
							json_object_get_string(hash_obj),
							json_object_get_string(status_obj),
							json_object_get_string(action_obj),
							json_object_get_string(service_obj),
							json_object_get_string(created_obj));
					}
				}
				printf("_________________________________________________________________________________________________________________"
					"________________________________________________\n");
				if (l_limit) { printf("\tlimit: %s \n", l_limit); DAP_DELETE(l_limit); }
				if (l_offset) { printf("\toffset: %s \n", l_offset); DAP_DELETE(l_offset); }
				if (summary_obj && json_object_get_type(summary_obj) == json_type_object) {
					json_object *tx_sum_obj = NULL, *accepted_obj = NULL, *rejected_obj = NULL;
					json_object_object_get_ex(summary_obj, "tx_sum", &tx_sum_obj);
					json_object_object_get_ex(summary_obj, "accepted_tx", &accepted_obj);
					json_object_object_get_ex(summary_obj, "rejected_tx", &rejected_obj);
					if (tx_sum_obj || accepted_obj || rejected_obj)
						printf("Total: %d transactions (Accepted: %d, Rejected: %d)\n",
							tx_sum_obj ? json_object_get_int(tx_sum_obj) : row_num,
							accepted_obj ? json_object_get_int(accepted_obj) : 0,
							rejected_obj ? json_object_get_int(rejected_obj) : 0);
				}
				return 0;
			}
		}

		// Check if this is a count response (single object with count)
		if (result_count == 1) {
			json_object *first_obj = json_object_array_get_idx(response->result_json_object, 0);
			json_object *count_obj = NULL;
			
			// Check for count response (version 1 or 2)
			if (json_object_object_get_ex(first_obj, "Number of transaction", &count_obj) ||
			    json_object_object_get_ex(first_obj, "total_tx_count", &count_obj)) {
                printf("Total transactions count: %"DAP_INT64_FORMAT"\n", json_object_get_int64(count_obj));
				return 0;
			}
		}

		// Handle transaction history list (should have 2 elements: transactions array + summary)
		if (result_count >= 2) {
			json_object *tx_array = json_object_array_get_idx(response->result_json_object, 0);
			json_object *summary_obj = json_object_array_get_idx(response->result_json_object, 1);			

			// Print transactions table header
			printf("_________________________________________________________________________________________________________________"
                "________________________________________________\n");
			printf(" # \t| Hash \t\t\t\t\t\t\t\t     | Status   | Action \t  | Token \t     | Time create\n");
			printf("_________________________________________________________________________________________________________________"
                "________________________________________________\n");

			// Print transaction list
			if (json_object_get_type(tx_array) == json_type_array) {
                char *l_limit = NULL;
                char *l_offset = NULL;
				int tx_count = json_object_array_length(tx_array);
				for (int i = 0; i < tx_count; i++) {
					json_object *tx_obj = json_object_array_get_idx(tx_array, i);
					if (!tx_obj) continue;

					json_object *tx_num_obj = NULL, *hash_obj = NULL;
					json_object *status_obj = NULL, *action_obj = NULL;
					json_object *token_obj = NULL, *j_obj_lim = NULL, *j_obj_off = NULL;
                    json_object *j_obj_create = NULL;

					// Get transaction fields (support both version 1 and 2)
                    if ((json_object_object_get_ex(tx_obj, "tx number", &tx_num_obj) ||
					    json_object_object_get_ex(tx_obj, "tx_num", &tx_num_obj)) &&
					    json_object_object_get_ex(tx_obj, "hash", &hash_obj) &&
					    json_object_object_get_ex(tx_obj, "status", &status_obj) &&
					    json_object_object_get_ex(tx_obj, "action", &action_obj) &&
					    json_object_object_get_ex(tx_obj, "token ticker", &token_obj) &&
                        json_object_object_get_ex(tx_obj, "tx created", &j_obj_create)) {                            

					    printf("%s\t| %-60s | %s\t| %-15s |  %-16s| %s\t|\n",
						   json_object_get_string(tx_num_obj),
						   json_object_get_string(hash_obj),
						   json_object_get_string(status_obj),
						   json_object_get_string(action_obj),
						   json_object_get_string(token_obj),
                           json_object_get_string(j_obj_create));
                    } else if (json_object_object_get_ex(tx_obj, "limit", &j_obj_lim)) {
                        json_object_object_get_ex(tx_obj, "offset", &j_obj_off);
                        l_limit = json_object_get_int64(j_obj_lim) ? dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_lim)) : dap_strdup_printf("unlimit");
                        if (j_obj_off)
                            l_offset = dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_off));
                    } else {
                        json_print_object(tx_obj, 0);
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
				json_object *network_obj = NULL, *chain_obj = NULL;
				json_object *tx_sum_obj = NULL, *accepted_obj = NULL, *rejected_obj = NULL;
				
				json_object_object_get_ex(summary_obj, "network", &network_obj);
				json_object_object_get_ex(summary_obj, "chain", &chain_obj);
				json_object_object_get_ex(summary_obj, "tx_sum", &tx_sum_obj);
				json_object_object_get_ex(summary_obj, "accepted_tx", &accepted_obj);
				json_object_object_get_ex(summary_obj, "rejected_tx", &rejected_obj);

				printf("\n=== Transaction History ===\n");
				if (network_obj && chain_obj) {
					printf("Network: %s, Chain: %s\n", 
						   json_object_get_string(network_obj),
						   json_object_get_string(chain_obj));
				}
				if (tx_sum_obj && accepted_obj && rejected_obj) {
					printf("Total: %d transactions (Accepted: %d, Rejected: %d)\n\n",
						   json_object_get_int(tx_sum_obj),
						   json_object_get_int(accepted_obj),
						   json_object_get_int(rejected_obj));
				}
			}

		} else {
			// Single transaction or unknown format - fallback to JSON print
			json_print_object(response->result_json_object, 0);
		}
	} else {
		// Single object response - could be a single transaction
		json_object *hash_obj = NULL;
		if (json_object_object_get_ex(response->result_json_object, "hash", &hash_obj)) {
			// This looks like a single transaction
			printf("\n=== Single Transaction ===\n");
			json_print_object(response->result_json_object, 0);
		} else {
			// Unknown format
			json_print_object(response->result_json_object, 0);
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
        json_print_object(response->result_json_object, 0);
        return 0;
    }

    // group_list: can be an array of objects { group_name: count } or an object { group_name: count }
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "group_list") != -1) {
        if (json_object_get_type(response->result_json_object) == json_type_array) {
            int len = json_object_array_length(response->result_json_object);
            if (len <= 0) { printf("Response array is empty\n"); return -2; }
            json_object *obj = json_object_array_get_idx(response->result_json_object, 0);
            json_object *arr = NULL, *total = NULL;
            if (obj && json_object_get_type(obj) == json_type_object) {
                // Support both spaced and underscored keys from different implementations
                json_object_object_get_ex(obj, "group_list", &arr);
                if (!arr) json_object_object_get_ex(obj, "group list", &arr);
                json_object_object_get_ex(obj, "total_count", &total);
                if (!total) json_object_object_get_ex(obj, "total count", &total);

                if (arr) {
                    int64_t groups_total = 0;
                    if (total)
                        groups_total = json_object_get_int64(total);
                    else if (json_object_get_type(arr) == json_type_array)
                        groups_total = (int64_t)json_object_array_length(arr);
                    else if (json_object_get_type(arr) == json_type_object)
                        groups_total = (int64_t)json_object_object_length(arr);

                    printf("Groups (total: %" DAP_INT64_FORMAT "):\n", groups_total);

                    if (json_object_get_type(arr) == json_type_array) {
                        for (size_t i = 0; i < (size_t)json_object_array_length(arr); i++) {
                            json_object *it = json_object_array_get_idx(arr, (int)i);
                            if (it && json_object_get_type(it) == json_type_object) {
                                json_object_object_foreach(it, key, val) {
                                    printf(" - %s: %" DAP_INT64_FORMAT "\n", key, json_object_get_int64(val));
                                }
                            }
                        }
                        return 0;
                    } else if (json_object_get_type(arr) == json_type_object) {
                        json_object_object_foreach(arr, key, val) {
                            printf(" - %s: %" DAP_INT64_FORMAT "\n", key, json_object_get_int64(val));
                        }
                        return 0;
                    }
                }
            }
            // fallback
            json_print_object(response->result_json_object, 0);
            return 0;
        }
    }

    // get_keys: array with one object containing keys_list
    if (dap_cli_server_cmd_check_option(cmd_param, 0, cmd_cnt, "get_keys") != -1) {
        if (json_object_get_type(response->result_json_object) == json_type_array) {
            json_object *obj = json_object_array_get_idx(response->result_json_object, 0);
            json_object *group = NULL, *keys = NULL;
            if (obj && json_object_get_type(obj) == json_type_object) {
                json_object_object_get_ex(obj, "group_name", &group);
                if (!group) json_object_object_get_ex(obj, "group name", &group);
                json_object_object_get_ex(obj, "keys_list", &keys);
                if (!keys) json_object_object_get_ex(obj, "keys list", &keys);
                if (keys && json_object_get_type(keys) == json_type_array) {
                    printf("Keys in group %s:\n", group ? json_object_get_string(group) : "<unknown>");
                    for (size_t i = 0; i < (size_t)json_object_array_length(keys); i++) {
                        json_object *it = json_object_array_get_idx(keys, (int)i);
                        json_object *k = NULL, *ts = NULL, *type = NULL;
                        if (it && json_object_get_type(it) == json_type_object) {
                            json_object_object_get_ex(it, "key", &k);
                            json_object_object_get_ex(it, "time", &ts);
                            json_object_object_get_ex(it, "type", &type);
                            printf(" - %s (%s) [%s]\n",
                                   k ? json_object_get_string(k) : "<no key>",
                                   ts ? json_object_get_string(ts) : "-",
                                   type ? json_object_get_string(type) : "-");
                        }
                    }
                    return 0;
                }
            }
        }
        json_print_object(response->result_json_object, 0);
        return 0;
    }
    
    return 0;
}