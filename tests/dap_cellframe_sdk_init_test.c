#include "dap_cellframe_sdk_init_test.h"

void dap_cellframe_sdk_init_test_run(void){
    dap_print_module_name("Massive init cellframe-sdk");
    dap_set_appname("test_cellframe_sdk");

    dap_assert(dap_common_init(dap_get_appname(), "test.log") == 0, "Init dap_common");

//    char l_config_dir[MAX_PATH] = {'\0'};
//    dap_sprintf(l_config_dir, "%s/etc", g_sys_dir_path);
//    dap_assert_PIF(dap_config_init(l_config_dir) == 0, "Can't initialization dap_config");

//    dap_assert_PIF((g_config = dap_config_open(dap_get_appname())) == NULL , "Can't init general configurations");

    dap_assert(dap_server_init(0) == 0 , "Init socket server module");

    dap_assert(dap_events_init( 0, 0 ) == 0, "Init events");
//    dap_events_t *l_events = dap_events_new( );
//    dap_assert_PIF(dap_events_start( l_events ) == 0, "Can't start events");

    dap_assert(dap_client_init() == 0, "Init dap client");

    dap_assert(dap_http_init() == 0, "Init http server module" );

    dap_assert(dap_http_folder_init() == 0, "Init http server module" );

    dap_assert(dap_enc_init() == 0, "Init encryption module" );

//    dap_assert_PIF(dap_chain_global_db_init(g_config) == 0, "Can't init global db module" );

//    dap_assert_PIF(dap_datum_mempool_init() == 0, "Init mempool module" );

//    dap_assert(dap_chain_init() ==0, "Init dap chain modules");

//    dap_assert(dap_chain_wallet_init() == 0, "Init dap chain wallet module");

//    dap_assert(dap_chain_cs_dag_init() != 0, "Init dap chain dag consensus module");

//    dap_assert(dap_chain_cs_dag_poa_init() !=0, "Init dap chain dag consensus PoA module");

//    dap_assert(dap_chain_cs_dag_pos_init() !=0, "Can't init dap chain dag consensus PoA module");

//    dap_assert(dap_chain_gdb_init() != 0, "Can't init dap chain gdb module");

}
