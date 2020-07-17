#pragma once

#include "dap_test.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_server.h"
#include "dap_http.h"
#include "dap_http_folder.h"
#include "dap_dns_server.h"


#include "dap_events.h"
#include "dap_enc.h"
#include "dap_enc_ks.h"
#include "dap_enc_http.h"

#include "dap_chain.h"
#include "dap_chain_wallet.h"

#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_dag_pos.h"
#include "dap_chain_cs_none.h"

#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_app.h"
#include "dap_chain_net_srv_app_db.h"
#include "dap_chain_net_srv_datum.h"
#include "dap_chain_net_bugreport.h"
#include "dap_chain_net_news.h"
#include "dap_chain_net_srv_geoip.h"

#ifdef DAP_OS_LINUX
#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_srv_vpn_cdb.h"
#include "dap_chain_net_srv_vpn_cdb_server_list.h"
#include "dap_chain_net_vpn_client.h"
#endif

#include "dap_chain_global_db.h"
#include "dap_chain_mempool.h"
#include "dap_chain_node.h"
#include "dap_chain_node_cli.h"

#include "dap_stream_session.h"
#include "dap_stream.h"
#include "dap_stream_ctl.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_net_srv_stake.h"

#include "dap_common.h"
#include "dap_client_remote.h"
#include "dap_client.h"
#include "dap_http_client.h"
//#include "dap_http_client_simple.h"
#include "dap_http_simple.h"
#include "dap_process_manager.h"
#include "dap_traffic_track.h"

#include "dap_file_utils.h"

#ifdef DAP_SUPPORT_PYTHON_PLUGINS
    #include "dap_chain_plugins.h"
#endif


#define ENC_HTTP_URL "/enc_init"
#define STREAM_CTL_URL "/stream_ctl"

#define STREAM_URL "/stream"
#define MEMPOOL_URL "/mempool"
#define MAIN_URL "/"


void dap_cellframe_sdk_init_test_run(void);
