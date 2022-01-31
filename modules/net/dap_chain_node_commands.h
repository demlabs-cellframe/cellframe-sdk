#ifndef DAP_CHAIN_NODE_COMMANDS_H
#define DAP_CHAIN_NODE_COMMANDS_H


extern const char *globalDB;
extern const char *globalDBCellsAdd;
extern const char *globalDBCellsAddParams;
extern const char *globalDBFlush;
extern const char *globalDBFlushParams;
extern const char *globalDBWlletInfoSet;

extern const char *node;
extern const char *nodeAdd;
extern const char *nodeAddParams;
extern const char *nodeDel;
extern const char *nodeDelParams;
extern const char *nodeLink;
extern const char *nodeLinkParams;
extern const char *nodeAlias;
extern const char *nodeAliasParams;
extern const char *nodeConnect;
extern const char *nodeConnectParams;
extern const char *nodeHandshake;
extern const char *nodeHandshakeParams;
extern const char *nodeDump;
extern const char *nodeDumpParams;

extern const char *ping;
extern const char *pingParams;

extern const char *traceroute;
extern const char *tracerouteHost;
extern const char *tracerouteHostParams;

extern const char *tracepath;
extern const char *tracepathHost;
extern const char *tracepathHostParams;

extern const char *version;
extern const char *versionParams;
extern const char *reternVersionNumber;
extern const char *reternVersionNumberParams;

extern const char *help;
extern const char *helpParams;
extern const char *bigHelpParams;

extern const char *wallet;
extern const char *walletParams;

extern const char *tokenUpdate;
extern const char *tokenDecl;
extern const char *tokenDeclSign;
extern const char *tokenEmit;
extern const char *tokenEmitParams;

extern const char *mempoolList;
extern const char *mempoolListParams;
extern const char *mempoolProc;
extern const char *mempoolProcParams;
extern const char *mempoolDelete;
extern const char *mempoolDeleteParams;
extern const char *mempoolAddCa;
extern const char *mempoolAddCaParams;

extern const char *chainCaPub;
extern const char *chainCaParams;
extern const char *chainCaCopy;
extern const char *chainCaCopyParams;

extern const char *txCreate;
extern const char *txCreateParams;
extern const char *txCondCreate;
extern const char *txCondCreateParams;
extern const char *txVerify;
extern const char *txVerifyParams;
extern const char *txHistory;
extern const char *txHistoryParams;

extern const char *ledger;
extern const char *ledgerListCoins;
extern const char *ledgerListCoinsParams;
extern const char *ledgerListCoinsCond;
extern const char *ledgerListCoinsCondParams;
extern const char *ledgerListAddrs;
extern const char *ledgerListAddrsParams;
extern const char *ledgerTx;
extern const char *ledgerTxParams;

extern const char *token;
extern const char *tokenList;
extern const char *tokenListParams;
extern const char *tokenInfo;
extern const char *tokenInfoParams;
extern const char *tokenTx;
extern const char *tokenTxParams;

extern const char *printLog;
extern const char *printLogParams;
extern const char *stats;
extern const char *statsCpu;

extern const char *gdbExport;
extern const char *gdbExportFilename;
extern const char *gdbExportFilenameParams;
extern const char *gdbImport;
extern const char *gdbImportFilename;
extern const char *gdbImportFilenameParams;

#endif // DAP_CHAIN_NODE_COMMANDS_H
