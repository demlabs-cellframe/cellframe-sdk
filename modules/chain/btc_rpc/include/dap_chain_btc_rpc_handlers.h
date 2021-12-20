#pragma once

#include "dap_json_rpc_request_handler.h"

void dap_chain_btc_rpc_registration_handlers();
void dap_chain_btc_rpc_unregistration_handlers();

void dap_chain_btc_rpc_handler_addmultisigaddress(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_addnode(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_backupwallet(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_createmultisig(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_createrawtransaction(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_decoderawtransaction(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_dumpprivkey(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_dumpwallet(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_encryptwallet(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getaccount(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getaccountaddress(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getaddednodeinfo(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getaddressesbyaccount(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getbalance(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getbestblockhash(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getblock(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getblockcount(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getblockhash(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getblocknumber(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getblocktemplate(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getconnectioncount(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getdifficulty(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getgenerate(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_gethashespersec(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getinfo(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getmemorypool(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getmininginfo(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);

void dap_chain_btc_rpc_handler_getnewaddress(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getpeerinfo(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getrawchangeaddress(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getrawmempool(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getrawtransaction(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getreceivedbyaccount(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getreceivedbyaddress(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_gettransaction(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_gettxout(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_gettxoutsetinfo(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_getwork(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);

void dap_chain_btc_rpc_handler_help(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);

void dap_chain_btc_rpc_handler_importprivkey(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_invalidateblock(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_keypoolrefill(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_listaccounts(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_listaddressgroupings(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_listreceivedbyaccount(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);

void dap_chain_btc_rpc_handler_listreceivedbyaccount(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_listreceivedbyaddress(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_listsinceblock(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_listtransactions(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_listunspent(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_listlockunspent(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_lockunspent(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_move(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);

void dap_chain_btc_rpc_handler_sendfrom(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_sendmany(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_sendrawtransaction(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_sendtoaddress(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_setaccount(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_setgenerate(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_settxfee(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_signmessage(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_signrawtransaction(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_stop(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_submitblock(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);

void dap_chain_btc_rpc_handler_validateaddress(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_verifymessage(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_walletlock(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_walletpassphrase(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_btc_rpc_handler_walletpassphrasechange(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response, const char *a_method);


