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
    if ( !dap_config_get_item_bool_default(g_config, "cli-server", "enabled", true) )
        return log_it( L_WARNING, "CLI server is disabled" ), 0;
    s_debug_cli = dap_config_get_item_bool_default(g_config, "cli-server", "debug-cli", false);
    if ( dap_cli_server_init(s_debug_cli, "cli-server") )
        return log_it(L_ERROR, "Can't init CLI server!"), -1;

    dap_cli_server_cmd_add("global_db", com_global_db, "Work with global database",
            "global_db flush\n"
                "\tFlushes the current state of the database to disk.\n\n"
            "global_db write -group <group_name> -key <key_name> -value <value>\n"
                "\tWrites a key value to a specified group in the database.\n\n"
            "global_db read -group <group_name> -key <key_name>\n"
                "\tReads a value by key from a specified group.\n\n"
            "global_db delete -group <group_name> -key <key_name>\n"
                "\tRemoves a value by key from a specified group.\n\n"
            "global_db group_list\n"
                "\tGets a list of groups in the database.\n\n"
            "global_db drop_table -group <group_name>\n"
                "\tPerforms deletion of the entire group in the database.\n\n"
            "global_db get_keys -group <group_name>\n"
                "\tGets all record keys from a specified group.\n"

//                    "global_db wallet_info set -addr <wallet address> -cell <cell id> \n\n"
            );
    dap_cli_server_cmd_add("mempool", com_signer, "Sign operations",
               "mempool sign -cert <priv_cert_name> -net <net_name> -chain <chain_name> -file <filename> [-mime {<SIGNER_FILENAME,SIGNER_FILENAME_SHORT,SIGNER_FILESIZE,SIGNER_DATE,SIGNER_MIME_MAGIC> | <SIGNER_ALL_FLAGS>}]\n"
               "mempool check -cert <priv_cert_name> -net <net_name> {-file <filename> | -hash <hash>} [-mime {<SIGNER_FILENAME,SIGNER_FILENAME_SHORT,SIGNER_FILESIZE,SIGNER_DATE,SIGNER_MIME_MAGIC> | <SIGNER_ALL_FLAGS>}]\n"
                                          );
    dap_cli_server_cmd_add("node", com_node, "Work with node",
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
    dap_cli_server_cmd_add ("token_update", com_token_update, "Token update",
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
                            "\n"
    );
    dap_cli_server_cmd_add ("wallet", com_tx_wallet, "Wallet operations",
                            "wallet list\n"
                            "wallet new -w <wallet_name> [-sign <sign_type>] [-restore <hex_value> | -restore_legacy <restore_string>] [-net <net_name>] [-force] [-password <password>]\n"
                            "wallet info {-addr <addr> | -w <wallet_name>} -net <net_name>\n"
                            "wallet activate -w <wallet_name> -password <password> [-ttl <password_ttl_in_minutes>]\n"
                            "wallet deactivate -w <wallet_name>>\n"
                            "wallet outputs {-addr <addr> | -w <wallet_name>} -net <net_name> -token <token_tiker> [{-cond [-type <cond_type>] | -value <uint256_value>}]\n"
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
                            "Hint:\n"
                                "\texample value_coins (only natural) 1.0 123.4567\n"
                                "\texample value_datoshi (only integer) 1 20 0.4321e+4\n"
    );

    // Token commands


    // Token commands
    dap_cli_server_cmd_add ("token_decl", com_token_decl, "Token declaration",
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
            "\n"
            );

    dap_cli_server_cmd_add("token_update_sign", com_token_decl_sign, "Token update add sign to datum",
                                        "token_update_sign -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <cert_list>\n"
                                        "\t Sign existent <datum hash> in mempool with <certs_list>\n"
    );
    // Token commands

    dap_cli_server_cmd_add ("token_decl_sign", com_token_decl_sign, "Token declaration add sign",
            "token_decl_sign -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <certs_list>\n"
            "\t Sign existent <datum_hash> in mempool with <certs_list>\n"
            );

    dap_cli_server_cmd_add ("token_emit", com_token_emit, "Token emission",
                            "token_emit { sign -emission <hash> | -token <mempool_token_ticker> -emission_value <value> -addr <addr> } "
                            "[-chain_emission <chain_name>] -net <net_name> -certs <cert_list>\n");

    dap_cli_cmd_t *l_cmd_mempool = dap_cli_server_cmd_add("mempool", com_mempool, "Command for working with mempool",
                           "mempool list -net <net_name> [-chain <chain_name>] [-addr <addr>] [-brief] [-limit] [-offset]\n"
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

    dap_cli_server_cmd_add ("chain_ca_pub", com_chain_ca_pub,
                                        "Add pubic certificate into the mempool to prepare its way to chains",
            "chain_ca_pub -net <net_name> [-chain <chain_name>] -ca_name <priv_cert_name>\n");

    // Transaction commands
    dap_cli_server_cmd_add ("tx_create", com_tx_create, "Make transaction",
            "tx_create -net <net_name> [-chain <chain_name>] -value <value> -token <token_ticker> -to_addr <addr> [-lock_before <unlock_time_in_RCF822>]"
            "{-from_wallet <wallet_name> | -from_emission <emission_hash> {-cert <cert_name> | -wallet_fee <wallet_name>}} -fee <value>\n");
    dap_cli_server_cmd_add ("tx_create_json", com_tx_create_json, "Make transaction",
                "tx_create_json -net <net_name> [-chain <chain_name>] -json <json_file_path>\n" );
    dap_cli_server_cmd_add ("tx_cond_create", com_tx_cond_create, "Make cond transaction",
                                        "tx_cond_create -net <net_name> -token <token_ticker> -w <wallet_name>"
                                        " -cert <pub_cert_name> -value <value_datoshi> -fee <value> -unit {B | SEC} -srv_uid <numeric_uid>\n" );
        dap_cli_server_cmd_add ("tx_cond_remove", com_tx_cond_remove, "Remove cond transactions and return funds from condition outputs to wallet",
                                        "tx_cond_remove -net <net_name> -hashes <hash1,hash2...> -w <wallet_name>"
                                        " -fee <value> -srv_uid <numeric_uid>\n" );
        dap_cli_server_cmd_add ("tx_cond_unspent_find", com_tx_cond_unspent_find, "Find cond transactions by wallet",
                                        "tx_cond_unspent_find -net <net_name> -srv_uid <numeric_uid> -w <wallet_name> \n" );

    dap_cli_server_cmd_add ("tx_verify", com_tx_verify, "Verifing transaction in mempool",
            "tx_verify -net <net_name> [-chain <chain_name>] -tx <tx_hash>\n" );

    // Transaction history
    dap_cli_server_cmd_add("tx_history", com_tx_history, "Transaction history (for address or by hash)",
            "tx_history  {-addr <addr> | {-w <wallet_name> | -tx <tx_hash>} -net <net_name>} [-chain <chain_name>] [-limit] [-offset] [-head]\n"
            "tx_history -all -net <net_name> [-chain <chain_name>] [-limit] [-offset] [-head]\n"
            "tx_history -count -net <net_name>\n");

	// Ledger info
    dap_cli_server_cmd_add("ledger", com_ledger, "Ledger information",
            "ledger list coins -net <net_name> [-limit] [-offset]\n"
            "ledger list threshold [-hash <tx_treshold_hash>] -net <net_name> [-limit] [-offset] [-head]\n"
            "ledger list balance -net <net_name> [-limit] [-offset] [-head]\n"
            "ledger info -hash <tx_hash> -net <net_name> [-unspent]\n");

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
                                        "gdb_import filename <filename_without_extension>");

    dap_cli_server_cmd_add ("remove", cmd_remove, "Delete chain files or global database",
           "remove -gdb\n"
           "remove -chains [-net <net_name> | -all]\n"
                     "Be careful, the '-all' option for '-chains' will delete all chains and won't ask you for permission!");

    // Decree create command
    dap_cli_server_cmd_add ("decree", cmd_decree, "Work with decree",
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

    dap_cli_server_cmd_add ("exec_cmd", com_exec_cmd, "Execute command on remote node",
            "exec_cmd -net <net_name> -addr <node_addr> -cmd <command,and,all,args,separated,by,commas>\n" );

    //Find command
    dap_cli_server_cmd_add("find", cmd_find, "The command searches for the specified elements by the specified attributes",
                           "find datum -net <net_name> [-chain <chain_name>] -hash <datum_hash>\n"
                           "\tSearches for datum by hash in the specified network in chains and mempool.\n"
                           "find atom -net <net_name> [-chain <chain_name>] -hash <atom_hash>\n"
                           "\tSearches for an atom by hash in a specified network in chains.\n"
                           "find decree -net <net_name> [-chain <chain_name>] -type <type_decree> [-where <chains|mempool>]\n"
                           "\tSearches for decrees by hash in the specified decree type in the specified network in its chains.\n"
                           "\tTypes decree: fee, owners, owners_min, stake_approve, stake_invalidate, min_value, "
                           "min_validators_count, ban, unban, reward, validator_max_weight, emergency_validators, check_signs_structure\n");


    dap_cli_server_cmd_add ("policy", com_policy, "Policy commands",
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
    dap_cli_server_cmd_add ("exit", com_exit, "Stop application and exit",
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
    dap_chain_node_client_deinit();
}
