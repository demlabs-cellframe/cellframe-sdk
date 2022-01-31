#include "dap_chain_node_commands.h"

const char *globalDB = "global_db";
const char *globalDBCellsAdd = "global_db cells add";
const char *globalDBCellsAddParams = "global_db cells add -cell <cell id> \n";
const char *globalDBFlush = "global_db flush";
const char *globalDBFlushParams = "global_db flush \n\n";
const char *globalDBWlletInfoSet = "global_db wallet_info set";

const char *node = "node";
const char *nodeAdd = "node add";
const char *nodeAddParams = "node add  -net <net name> -addr {<node address> | -alias <node alias>} {-port <port>} -cell <cell id>  {-ipv4 <ipv4 external address> | -ipv6 <ipv6 external address>}\n\n";
const char *nodeDel = "node del";
const char *nodeDelParams = "node del  -net <net name> -addr <node address> | -alias <node alias>\n\n";
const char *nodeLink = "node link";
const char *nodeLinkParams = "node link {add|del}  -net <net name> {-addr <node address> | -alias <node alias>} -link <node address>\n\n";
const char *nodeAlias = "node alias";
const char *nodeAliasParams = "node alias -addr <node address> -alias <node alias>\n\n";
const char *nodeConnect = "node connect";
const char *nodeConnectParams = "node connect {<node address> | -alias <node alias> | auto}\n\n";
const char *nodeHandshake = "node handshake";
const char *nodeHandshakeParams = "node handshake {<node address> | -alias <node alias>}\n";
const char *nodeDump = "node dump";
const char *nodeDumpParams = "node dump -net <net name> [ -addr <node address> | -alias <node alias>] [-full]\n\n";

const char *ping = "ping";
const char *pingParams = "ping [-c <count>] host\n";

const char *traceroute = "traceroute";
const char *tracerouteHost = "traceroute host";
const char *tracerouteHostParams = "traceroute host\n";

const char *tracepath = "tracepath";
const char *tracepathHost = "tracepath host";
const char *tracepathHostParams = "tracepath host\n";

const char *version = "version";
const char *versionParams = "version\n";
const char *reternVersionNumber = "Return version number";
const char *reternVersionNumberParams = "\tReturn version number\n";

const char *help = "help";
const char *helpParams = "help [<command>]\n";
const char *bigHelpParams = "\tObtain help for <command> or get the total list of the commands\n";

const char *wallet = "wallet";
const char *walletParams = "wallet [new -w <wallet_name> [-sign <sign_type>] [-restore <hex value>] [-net <net_name>] [-force]| list | info -addr <addr> -w <wallet_name> -net <net_name>]\n";

const char *tokenUpdate = "token_update";
const char *tokenDecl = "token_decl";
const char *tokenDeclSign = "token_decl_sign";
const char *tokenEmit = "token_emit";
const char *tokenEmitParams = "token_emit -net <net name> -chain_emission <chain for emission> -chain_base_tx <chain for base tx> -addr <addr> -token <token ticker> -certs <cert> -emission_value <val>\n";

const char *mempoolList = "mempool_list";
const char *mempoolListParams = "mempool_list -net <net name>\n";
const char *mempoolProc = "mempool_proc";
const char *mempoolProcParams = "mempool_proc -net <net name> -datum <datum hash>\n";
const char *mempoolDelete = "mempool_delete";
const char *mempoolDeleteParams = "mempool_delete -net <net name> -datum <datum hash>\n";
const char *mempoolAddCa = "mempool_add_ca";
const char *mempoolAddCaParams = "mempool_add_ca -net <net name> [-chain <chain name>] -ca_name <Certificate name>\n";

const char *chainCaPub = "chain_ca_pub";
const char *chainCaParams = "chain_ca -net <net name> [-chain <chain name>] -ca_name <Certificate name>\n";
const char *chainCaCopy = "chain_ca_copy";
const char *chainCaCopyParams = "chain_ca -net <net name> [-chain <chain name>] -ca_name <Public certificate name>\n";

const char *txCreate = "tx_create";
const char *txCreateParams = "tx_create -net <net name> -chain <chain name> -from_wallet <name> -to_addr <addr> -token <token ticker> -value <value> [-fee <addr> -value_fee <val>]\n";
const char *txCondCreate = "tx_cond_create";
const char *txCondCreateParams = "tx_cond_create -net <net name> -token <token_ticker> -wallet_f <wallet_from> -wallet_t <wallet_to> -value <value_datoshi> -unit <mb|kb|b|sec|day> -service <vpn>\n";
const char *txVerify = "tx_verify";
const char *txVerifyParams = "tx_verify -net <net name> -chain <chain name> -tx <tx_hash>\n";
const char *txHistory = "tx_history";
const char *txHistoryParams = "tx_history  [-addr <addr> | -w <wallet name> | -tx <tx_hash>] -net <net name> -chain <chain name>\n";

const char *ledger = "ledger";
const char *ledgerListCoins = "ledger list coins";
const char *ledgerListCoinsParams = "ledger list coins -net <network name>\n";
const char *ledgerListCoinsCond = "ledger list coins_cond";
const char *ledgerListCoinsCondParams = "ledger list coins_cond -net <network name>\n";
const char *ledgerListAddrs = "ledger list addrs";
const char *ledgerListAddrsParams = "ledger list addrs -net <network name>\n";
const char *ledgerTx = "ledger tx";
const char *ledgerTxParams = "ledger tx [all | -addr <addr> | -w <wallet name> | -tx <tx_hash>] [-chain <chain name>] -net <network name>\n";

const char *token = "token";
const char *tokenList = "token list";
const char *tokenListParams = "token list -net <network name>\n";
const char *tokenInfo = "token info";
const char *tokenInfoParams = "token info -net <network name> -name <token name>\n";
const char *tokenTx = "token tx";
const char *tokenTxParams = "token tx [all | -addr <wallet_addr> | -wallet <wallet_name>] -name <token name> -net <network name> [-page_start <page>] [-page <page>]\n";

const char *printLog = "print_log";
const char *printLogParams = "print_log [ts_after <timestamp >] [limit <line numbers>]\n";
const char *stats = "stats";
const char *statsCpu = "stats cpu";

const char *gdbExport = "gdb_export";
const char *gdbExportFilename = "gdb_export filename";
const char *gdbExportFilenameParams = "gdb_export filename <filename without extension>";
const char *gdbImport = "gdb_import";
const char *gdbImportFilename = "gdb_import filename";
const char *gdbImportFilenameParams = "gdb_import filename <filename without extension>";
