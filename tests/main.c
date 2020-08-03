#include "dap_test.h"
#include "dap_test_generator.h"
#include "dap_cellframe_sdk_init_test.h"

const char *test_cfg_files = "# General section\n"
        "[general]\n"
        "debug_mode=true\n"
        "debug_dump_stream_headers=false\n"
        "# seed mode. WARNING. Used true only when you start the new network\n"
        "#seed_mode=false\n"
        "auto_online=false\n\n"
        "# Console\n\n"
        "# Server part\n"
        "[server]\n"
        "#   By default you don't need to open you to the world\n"
        "enabled=false\n"
        "listen_address=0.0.0.0\n"
        "listen_port_tcp=8079\n"
        "news_url_enabled=false\n"
        "bugreport_url_enabled=false\n\n"
        "# Builtin DNS server\n"
        "[dns_server]\n"
        "enabled=false\n"
        "bootstrap_balancer=true\n\n"
        "[srv]\n"
        "order_signed_only=false\n\n"
        "[srv_dns]\n"
        "enabled=false\n"
        "pricelist=[]\n\n"
        "# Mempool\n"
        "[mempool]\n"
        "# Automaticaly true if master node\n"
        "#auto_proc=false\n\n"
        "# Central Database\n"
        "[cdb]\n"
        "enabled=false\n"
        "servers_list_enabled=false\n"
        "servers_list_networks=[kelvin-testnet,private]\n\n"
        "# Central Database authorization\n"
        "[cdb_auth]\n"
        "enabled=false\n"
        "domain=mydomain\n"
        "tx_cond_create=false\n"
        "registration_open=true\n"
        "# List of condition templates, created for authorized users. Format of condition:\n"
        "# <wallet name>:<Value per transaction>:<Minimum time(seconds) between transactions>:<network name>\n"
        "# tx_cond_templates=[mywallet0:0.00001:3600:KELT:kelvin-testnet,mywallet1:0.000001:3600:cETH:kelvin-testnet,mywallet0:1:10:WOOD:private]\n\n"
        "# VPN stream channel processing module\n"
        "[srv_vpn]\n"
        "#   Turn to true if you want to share VPN service from you node\n"
        "enabled=false\n"
        "geoip_enabled=false\n"
        "#   List of loca security access groups. Built in: expats,admins,services,nobody,everybody\n"
        "network_address=10.11.12.0\n"
        "network_mask=255.255.255.0\n"
        "pricelist=[kelvin-testnet:0.00001:KELT:3600:SEC:mywallet0,kelvin-testnet:0.00001:cETH:3600:SEC:mywallet1,private:1:WOOD:10:SEC:mywallet0]\n\n"
        "# Console interface server\n"
        "[conserver]\n"
        "enabled=true\n"
        "#listen_port_tcp=12345\n"
        "listen_unix_socket_path=/opt/cellframe-node/var/run/node_cli\n"
        "# Default permissions 770\n"
        "#listen_unix_socket_permissions=770\n\n"
        "# Application Resources\n"
        "[resources]\n"
        "#   0 means auto detect\n"
        "threads_cnt=0\n"
        "pid_path=/opt/cellframe-node/var/run/cellframe-node.pid\n"
        "log_file=/opt/cellframe-node/var/log/cellframe-node.log\n"
        "wallets_path=/opt/cellframe-node/var/lib/wallet\n"
        "geoip_db_path=share/geoip/GeoLite2-City.mmdb\n"
        "ca_folders=[/opt/cellframe-node/var/lib/ca,/opt/cellframe-node/share/ca]\n"
        "dap_global_db_path=/opt/cellframe-node/var/lib/global_db\n"
        "dap_global_db_driver=cdb\n\n"
        "# Plugins\n"
        "[plugins]\n"
        //    dap_mkdir_with_parents(dap_strjoin(NULL, g_sys_dir_path, "var/", "log/");
        //    dap_test_msg(" G path: %s \n get_aap: %s", g_sys_dir_path, dap_get_appname());
        "# Load Python plugins\n"
        "py_load=false\n"
        "# Plugins path\n"
        "py_path=/opt/cellframe-node/var/plugins\n";

void dap_cellframe_sdk_creat_config_files_test();

char * dap_cellframe_sdk_str_replaced(const char *a_str_in, const char *a_str_search, const char *a_str_replaced){
    char *l_out = NULL;
    size_t l_out_size = 0;
    size_t l_str_in_size = dap_strlen(a_str_in);
    size_t l_str_search_size = dap_strlen(a_str_search);
    size_t l_str_replaces_size = dap_strlen(a_str_replaced);
    size_t l_viewed = 0;
    while (l_viewed  < l_str_in_size){
        char *l_tmp = DAP_NEW_SIZE(char, l_str_search_size);
        memcpy(l_tmp, a_str_in + l_viewed, l_str_search_size);
        if (memcmp(l_tmp, a_str_search, l_str_search_size) == 0){
            size_t l_new_out_len = l_out_size + l_str_replaces_size;
            char *l_new_out = DAP_NEW_SIZE(char, l_new_out_len);
            memcpy(l_new_out, l_out, l_out_size);
            memcpy(l_new_out + l_out_size, a_str_replaced, l_str_replaces_size);
            DAP_FREE(l_out);
            l_out = l_new_out;
            l_out_size = l_new_out_len;
            l_viewed += (l_str_search_size - 1);
        } else {
            size_t l_new_out_len = l_out_size + 1;
            char *l_new_out = DAP_NEW_SIZE(char, l_new_out_len);
            memcpy(l_new_out, l_out, l_out_size);
            memcpy(l_new_out + l_out_size, a_str_in + l_viewed, 1);
            DAP_FREE(l_out);
            l_out = l_new_out;
            l_out_size = l_new_out_len;
        }
        l_viewed += 1;
        DAP_FREE(l_tmp);
    }
    return l_out;
}

int main (int argc, char **argv){
    dap_print_module_name("First test. Test run");
    dap_assert_PIF((0 != 1) , " 0 != 1");
    size_t l_argv_zero_len = dap_strlen(argv[0]);
    size_t count_slesh = 0;
    size_t l_new_str = 0;
    for (size_t i=0 ; i < l_argv_zero_len; i++){
        if (argv[0][i] == '/')
            count_slesh++;
    }
    for (size_t i=0 ; i < l_argv_zero_len; i++){
        if (count_slesh == 0)
            break;
        if (argv[0][i] == '/')
            count_slesh--;
        l_new_str++;
    }
    l_new_str++;
    g_sys_dir_path = DAP_NEW_SIZE(char, l_new_str);
    memcpy(g_sys_dir_path, argv[0], l_new_str);
    g_sys_dir_path[l_new_str - 1] = '\0';
    dap_cellframe_sdk_creat_config_files_test();
    dap_cellframe_sdk_init_test_run();
    return 0;
}

void dap_cellframe_sdk_creat_config_files_test(){
    char *l_str = dap_cellframe_sdk_str_replaced(test_cfg_files, "/opt/cellframe-node/", g_sys_dir_path);
    FILE *file_main_cfg = fopen(dap_strjoin(NULL, g_sys_dir_path, "test_cellframe_sdk.cfg", NULL), "wt");
    fwrite(l_str, sizeof(char), strlen(l_str), file_main_cfg);
//    fputs()
    fclose(file_main_cfg);
    DAP_FREE(l_str);
}
