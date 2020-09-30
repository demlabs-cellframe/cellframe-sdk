#include "dap_chain_btc_rpc_handlers.h"

void dap_chain_btc_rpc_registration_handlers(){
    dap_json_rpc_registration_request_handler("addmultisigaddress", dap_chain_btc_rpc_handler_addmultisigaddress);
    dap_json_rpc_registration_request_handler("addnode", dap_chain_btc_rpc_handler_addnode);
    dap_json_rpc_registration_request_handler("backupwallet", dap_chain_btc_rpc_handler_backupwallet);
    dap_json_rpc_registration_request_handler("createmultisig", dap_chain_btc_rpc_handler_createmultisig);
    dap_json_rpc_registration_request_handler("createrawtransaction", dap_chain_btc_rpc_handler_createrawtransaction);
    dap_json_rpc_registration_request_handler("decoderawtransaction", dap_chain_btc_rpc_handler_decoderawtransaction);
    dap_json_rpc_registration_request_handler("dumpprivkey", dap_chain_btc_rpc_handler_dumpprivkey);
    dap_json_rpc_registration_request_handler("dumpwallet", dap_chain_btc_rpc_handler_dumpwallet);
    dap_json_rpc_registration_request_handler("encryptwallet", dap_chain_btc_rpc_handler_encryptwallet);
    dap_json_rpc_registration_request_handler("getaccount", dap_chain_btc_rpc_handler_getaccount);
    dap_json_rpc_registration_request_handler("getaccountaddress", dap_chain_btc_rpc_handler_getaccountaddress);
    dap_json_rpc_registration_request_handler("getaddednodeinfo", dap_chain_btc_rpc_handler_getaddednodeinfo);
    dap_json_rpc_registration_request_handler("getaddressesbyaccount", dap_chain_btc_rpc_handler_getaddressesbyaccount);
    dap_json_rpc_registration_request_handler("getbalance", dap_chain_btc_rpc_handler_getbalance);
    dap_json_rpc_registration_request_handler("getbestblockhash", dap_chain_btc_rpc_handler_getbestblockhash);
    dap_json_rpc_registration_request_handler("getblock", dap_chain_btc_rpc_handler_getblock);
    dap_json_rpc_registration_request_handler("getblockcount", dap_chain_btc_rpc_handler_getblockcount);
    dap_json_rpc_registration_request_handler("getblockhash", dap_chain_btc_rpc_handler_getblockhash);
    dap_json_rpc_registration_request_handler("getblocknumber", dap_chain_btc_rpc_handler_getblocknumber);
    dap_json_rpc_registration_request_handler("getblocktemplate", dap_chain_btc_rpc_handler_getblocktemplate);
    dap_json_rpc_registration_request_handler("getconnectioncount", dap_chain_btc_rpc_handler_getconnectioncount);
    dap_json_rpc_registration_request_handler("getdifficulty", dap_chain_btc_rpc_handler_getdifficulty);
    dap_json_rpc_registration_request_handler("getgenerate", dap_chain_btc_rpc_handler_getgenerate);
    dap_json_rpc_registration_request_handler("gethashespersec", dap_chain_btc_rpc_handler_gethashespersec);
    dap_json_rpc_registration_request_handler("getinfo", dap_chain_btc_rpc_handler_getinfo);
    dap_json_rpc_registration_request_handler("getmemorypool", dap_chain_btc_rpc_handler_getmemorypool);
    dap_json_rpc_registration_request_handler("getmininginfo", dap_chain_btc_rpc_handler_getmininginfo);
    dap_json_rpc_registration_request_handler("getnewaddress", dap_chain_btc_rpc_handler_getnewaddress);
    dap_json_rpc_registration_request_handler("getpeerinfo", dap_chain_btc_rpc_handler_getpeerinfo);
    dap_json_rpc_registration_request_handler("getrawchangeaddress", dap_chain_btc_rpc_handler_getrawchangeaddress);
    dap_json_rpc_registration_request_handler("getrawmempool", dap_chain_btc_rpc_handler_getrawmempool);
    dap_json_rpc_registration_request_handler("getrawtransaction", dap_chain_btc_rpc_handler_getrawtransaction);
    dap_json_rpc_registration_request_handler("getreceivedbyaccount", dap_chain_btc_rpc_handler_getreceivedbyaccount);
    dap_json_rpc_registration_request_handler("getreceivedbyaddress", dap_chain_btc_rpc_handler_getreceivedbyaddress);
    dap_json_rpc_registration_request_handler("gettransaction", dap_chain_btc_rpc_handler_gettransaction);
    dap_json_rpc_registration_request_handler("gettxout", dap_chain_btc_rpc_handler_gettxout);
    dap_json_rpc_registration_request_handler("gettxoutsetinfo", dap_chain_btc_rpc_handler_gettxoutsetinfo);
    dap_json_rpc_registration_request_handler("getwork", dap_chain_btc_rpc_handler_getwork);
    dap_json_rpc_registration_request_handler("help", dap_chain_btc_rpc_handler_help);
    dap_json_rpc_registration_request_handler("importprivkey", dap_chain_btc_rpc_handler_importprivkey);
    dap_json_rpc_registration_request_handler("invalidateblock", dap_chain_btc_rpc_handler_invalidateblock);
    dap_json_rpc_registration_request_handler("keypoolrefill", dap_chain_btc_rpc_handler_keypoolrefill);
    dap_json_rpc_registration_request_handler("listaccounts", dap_chain_btc_rpc_handler_listaccounts);
    dap_json_rpc_registration_request_handler("listaddressgroupings", dap_chain_btc_rpc_handler_listaddressgroupings);
    dap_json_rpc_registration_request_handler("listreceivedbyaccount", dap_chain_btc_rpc_handler_listreceivedbyaccount);
    dap_json_rpc_registration_request_handler("listreceivedbyaddress", dap_chain_btc_rpc_handler_listreceivedbyaddress);
    dap_json_rpc_registration_request_handler("listsinceblock", dap_chain_btc_rpc_handler_listsinceblock);
    dap_json_rpc_registration_request_handler("listtransactions", dap_chain_btc_rpc_handler_listtransactions);
    dap_json_rpc_registration_request_handler("listunspent", dap_chain_btc_rpc_handler_listunspent);
    dap_json_rpc_registration_request_handler("listlockunspent", dap_chain_btc_rpc_handler_listlockunspent);
    dap_json_rpc_registration_request_handler("lockunspent", dap_chain_btc_rpc_handler_lockunspent);
    dap_json_rpc_registration_request_handler("move", dap_chain_btc_rpc_handler_move);
    dap_json_rpc_registration_request_handler("sendfrom", dap_chain_btc_rpc_handler_sendfrom);
    dap_json_rpc_registration_request_handler("sendmany", dap_chain_btc_rpc_handler_sendmany);
    dap_json_rpc_registration_request_handler("sendrawtransaction", dap_chain_btc_rpc_handler_sendrawtransaction);
    dap_json_rpc_registration_request_handler("sendtoaddress", dap_chain_btc_rpc_handler_sendtoaddress);
    dap_json_rpc_registration_request_handler("setaccount", dap_chain_btc_rpc_handler_setaccount);
    dap_json_rpc_registration_request_handler("setgenerate", dap_chain_btc_rpc_handler_setgenerate);
    dap_json_rpc_registration_request_handler("settxfee", dap_chain_btc_rpc_handler_settxfee);
    dap_json_rpc_registration_request_handler("signmessage", dap_chain_btc_rpc_handler_signmessage);
    dap_json_rpc_registration_request_handler("signrawtransaction", dap_chain_btc_rpc_handler_signrawtransaction);
    dap_json_rpc_registration_request_handler("stop", dap_chain_btc_rpc_handler_stop);
    dap_json_rpc_registration_request_handler("submitblock", dap_chain_btc_rpc_handler_submitblock);
    dap_json_rpc_registration_request_handler("validateaddress", dap_chain_btc_rpc_handler_validateaddress);
    dap_json_rpc_registration_request_handler("verifymessage", dap_chain_btc_rpc_handler_verifymessage);
    dap_json_rpc_registration_request_handler("walletlock", dap_chain_btc_rpc_handler_walletlock);
    dap_json_rpc_registration_request_handler("walletpassphrase", dap_chain_btc_rpc_handler_walletpassphrase);
    dap_json_rpc_registration_request_handler("walletpassphrasechange", dap_chain_btc_rpc_handler_walletpassphrasechange);
}

void dap_chain_btc_rpc_unregistration_handlers(){
    dap_json_rpc_unregistration_request_handler("addmultisigaddress");
    dap_json_rpc_unregistration_request_handler("addnode");
    dap_json_rpc_unregistration_request_handler("backupwallet");
    dap_json_rpc_unregistration_request_handler("createmultisig");
    dap_json_rpc_unregistration_request_handler("createrawtransaction");
    dap_json_rpc_unregistration_request_handler("decoderawtransaction");
    dap_json_rpc_unregistration_request_handler("dumpprivkey");
    dap_json_rpc_unregistration_request_handler("dumpwallet");
    dap_json_rpc_unregistration_request_handler("encryptwallet");
    dap_json_rpc_unregistration_request_handler("getaccount");
    dap_json_rpc_unregistration_request_handler("getaccountaddress");
    dap_json_rpc_unregistration_request_handler("getaddednodeinfo");
    dap_json_rpc_unregistration_request_handler("getaddressesbyaccount");
    dap_json_rpc_unregistration_request_handler("getbalance");
    dap_json_rpc_unregistration_request_handler("getbestblockhash");
    dap_json_rpc_unregistration_request_handler("getblock");
    dap_json_rpc_unregistration_request_handler("getblockcount");
    dap_json_rpc_unregistration_request_handler("getblockhash");
    dap_json_rpc_unregistration_request_handler("getblocknumber");
    dap_json_rpc_unregistration_request_handler("getblocktemplate");
    dap_json_rpc_unregistration_request_handler("getconnectioncount");
    dap_json_rpc_unregistration_request_handler("getdifficulty");
    dap_json_rpc_unregistration_request_handler("getgenerate");
    dap_json_rpc_unregistration_request_handler("gethashespersec");
    dap_json_rpc_unregistration_request_handler("getinfo");
    dap_json_rpc_unregistration_request_handler("getmemorypool");
    dap_json_rpc_unregistration_request_handler("getmininginfo");
    dap_json_rpc_unregistration_request_handler("getnewaddress");
    dap_json_rpc_unregistration_request_handler("getpeerinfo");
    dap_json_rpc_unregistration_request_handler("getrawchangeaddress");
    dap_json_rpc_unregistration_request_handler("getrawmempool");
    dap_json_rpc_unregistration_request_handler("getrawtransaction");
    dap_json_rpc_unregistration_request_handler("getreceivedbyaccount");
    dap_json_rpc_unregistration_request_handler("getreceivedbyaddress");
    dap_json_rpc_unregistration_request_handler("gettransaction");
    dap_json_rpc_unregistration_request_handler("gettxout");
    dap_json_rpc_unregistration_request_handler("gettxoutsetinfo");
    dap_json_rpc_unregistration_request_handler("getwork");
    dap_json_rpc_unregistration_request_handler("help");
    dap_json_rpc_unregistration_request_handler("importprivkey");
    dap_json_rpc_unregistration_request_handler("invalidateblock");
    dap_json_rpc_unregistration_request_handler("keypoolrefill");
    dap_json_rpc_unregistration_request_handler("listaccounts");
    dap_json_rpc_unregistration_request_handler("listaddressgroupings");
    dap_json_rpc_unregistration_request_handler("listreceivedbyaccount");
    dap_json_rpc_unregistration_request_handler("listreceivedbyaddress");
    dap_json_rpc_unregistration_request_handler("listsinceblock");
    dap_json_rpc_unregistration_request_handler("listtransactions");
    dap_json_rpc_unregistration_request_handler("listunspent");
    dap_json_rpc_unregistration_request_handler("listlockunspent");
    dap_json_rpc_unregistration_request_handler("lockunspent");
    dap_json_rpc_unregistration_request_handler("move");
    dap_json_rpc_unregistration_request_handler("sendfrom");
    dap_json_rpc_unregistration_request_handler("sendmany");
    dap_json_rpc_unregistration_request_handler("sendrawtransaction");
    dap_json_rpc_unregistration_request_handler("sendtoaddress");
    dap_json_rpc_unregistration_request_handler("setaccount");
    dap_json_rpc_unregistration_request_handler("setgenerate");
    dap_json_rpc_unregistration_request_handler("settxfee");
    dap_json_rpc_unregistration_request_handler("signmessage");
    dap_json_rpc_unregistration_request_handler("signrawtransaction");
    dap_json_rpc_unregistration_request_handler("stop");
    dap_json_rpc_unregistration_request_handler("submitblock");
    dap_json_rpc_unregistration_request_handler("validateaddress");
    dap_json_rpc_unregistration_request_handler("verifymessage");
    dap_json_rpc_unregistration_request_handler("walletlock");
    dap_json_rpc_unregistration_request_handler("walletpassphrase");
    dap_json_rpc_unregistration_request_handler("walletpassphrasechange");
}
