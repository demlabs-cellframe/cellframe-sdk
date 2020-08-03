#include "dap_cellframe_sdk_init_test.h"

void dap_cellframe_sdk_init_test_run(void){
    dap_print_module_name("Massive init cellframe-sdk");
    dap_set_appname("test_cellframe_sdk");

    dap_assert(dap_common_init(dap_get_appname(), "test.log") == 0, "Init dap_common");

    dap_assert(dap_config_init(g_sys_dir_path) == 0, "Initialization dap_config");
    dap_mkdir_with_parents(dap_strjoin(NULL, g_sys_dir_path, "var/", "run/", NULL));

    dap_assert((g_config = dap_config_open(dap_get_appname())) != NULL , "Init general configurations");

    dap_assert(dap_server_init(0) == 0 , "Init socket server module");

    dap_assert(dap_events_init( 0, 0 ) == 0, "Init events");
    dap_events_t *l_events = dap_events_new( );
    dap_assert(dap_events_start( l_events ) == 0, "Start events");

    dap_assert(dap_client_init() == 0, "Init dap client");

    dap_assert(dap_http_init() == 0, "Init http server module" );

    dap_assert(dap_http_folder_init() == 0, "Init http server module" );

    dap_assert(dap_enc_init() == 0, "Init encryption module" );

    dap_assert(dap_chain_global_db_init(g_config) == 0, "Init global db module" );

    dap_assert(dap_datum_mempool_init() == 0, "Init mempool module" );

    dap_assert(dap_chain_init() ==0, "Init dap chain modules");

    dap_assert(dap_chain_wallet_init() == 0, "Init dap chain wallet module");

    dap_assert(dap_chain_cs_dag_init() == 0, "Init dap chain dag consensus module");

    dap_assert(dap_chain_cs_dag_poa_init() ==0, "Init dap chain dag consensus PoA module");

    dap_assert(dap_chain_cs_dag_pos_init() ==0, "Init dap chain dag consensus PoA module");

    dap_assert(dap_chain_gdb_init() == 0, "Init dap chain gdb module");

    dap_assert(dap_chain_net_init() == 0, "Init dap chain network module");

    dap_assert(dap_chain_net_srv_init(g_config) == 0, "Init dap chain network service module");

    dap_assert(dap_chain_net_srv_app_init() == 0, "Init dap chain network service applications module");

    dap_assert(dap_chain_net_srv_datum_init() == 0, "Init dap chain network service datum module");

    if(dap_config_get_item_bool_default(g_config, "srv_vpn", "geoip_enabled", false)) {
        dap_assert(chain_net_geoip_init(g_config) == 0, "Init geoip module");
    }

    dap_assert(enc_http_init() == 0, "Init encryption http session storage module" );

    dap_assert(dap_stream_init(dap_config_get_item_bool_default(g_config,"general","debug_dump_stream_headers",false)) == 0,
         "Init stream server module" );

    dap_assert(dap_stream_ctl_init(DAP_ENC_KEY_TYPE_OAES, 32) == 0, "Init stream control module" );

    dap_assert(dap_http_simple_module_init() == 0, "Init http simple module");

    dap_assert(dap_chain_node_cli_init(g_config) == 0, "Init server for console" );

//    dap_assert(sig_unix_handler_init(dap_config_get_item_str_default(g_config,
//                                                                  "resources",
//                                                                  "pid_path",
//                                                                  "/tmp")) == 0, "Init sig unix handler module");

    dap_assert(dap_chain_node_mempool_init() == 0, "Init automatic mempool processing" );

    dap_assert(dap_stream_ch_chain_init( ) == 0, "Init stream ch");
    dap_assert(dap_stream_ch_chain_net_init( ) == 0, "Init stream ch net");

    dap_assert(dap_stream_ch_chain_net_srv_init() == 0, "Init stream ch net srv");

    dap_assert(dap_chain_net_srv_xchange_init() == 1, "Provide exchange capability");
    dap_assert(dap_chain_net_srv_stake_init() == 1, "Start delegated stake service");

    dap_stream_deinit();
    dap_stream_ctl_deinit();
    dap_http_folder_deinit();
    dap_http_deinit();
    dap_server_deinit();
    dap_enc_ks_deinit();
    dap_chain_node_mempool_deinit();
//    dap_chain_net_srv_xchange_deinit();
    dap_chain_net_srv_stake_deinit();

    dap_config_close( g_config );
    dap_common_deinit();

}
