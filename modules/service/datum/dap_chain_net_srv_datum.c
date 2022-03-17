/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include "dap_chain_net_srv_datum.h"

#include "dap_file_utils.h"

#include "dap_chain_mempool.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"

#define LOG_TAG "chain_net_srv_datum"

static int s_srv_datum_cli(int argc, char ** argv, char **a_str_reply);

int dap_chain_net_srv_datum_init()
{
    dap_chain_node_cli_cmd_item_create("srv_datum", s_srv_datum_cli, "Service Datum commands", 
        "srv_datum -net <chain net name> -chain <chain name> datum save -datum <datum hash>\n"
            "\tSaving datum from mempool to file.\n\n"
        "srv_datum -net <chain net name> -chain <chain name> datum load -datum <datum hash>\n"
            "\tLoad datum custum from file to mempool.\n\n");

    return 0;
}

void dap_chain_net_srv_datum_deinit()
{

}

uint8_t * dap_chain_net_srv_file_datum_data_read(char * a_path, size_t *a_data_size) {
    uint8_t *l_datum_data = NULL;
    size_t l_datum_data_size = 0;
    FILE * l_file = fopen(a_path, "rb");
    if( l_file ){
        fseek(l_file, 0L, SEEK_END);
        //uint64_t l_file_size = ftell(l_file);
        l_datum_data_size = ftell(l_file);
        rewind(l_file);
        l_datum_data = DAP_NEW_SIZE(uint8_t, l_datum_data_size);
        if ( fread(l_datum_data, 1, l_datum_data_size, l_file ) != l_datum_data_size ){
            log_it(L_ERROR, "Can't read %"DAP_UINT64_FORMAT_U" bytes from the disk!", l_datum_data_size);
            DAP_DELETE(l_datum_data);
            if( l_file )
                fclose(l_file);
            return NULL;
        }
    }
    if( l_file )
        fclose(l_file);
    *a_data_size = l_datum_data_size;
    return l_datum_data;
}

char* dap_chain_net_srv_datum_custom_add(dap_chain_t * a_chain, const uint8_t *a_data, size_t a_data_size) {

    dap_chain_datum_t * l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_CUSTOM, a_data, a_data_size);
    if( l_datum == NULL){
        log_it(L_ERROR, "Failed to create custom datum.");
        return NULL;
    }

    // Finaly add datum to mempool
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, a_chain);
    return l_hash_str;
}

static int s_srv_datum_cli(int argc, char ** argv, char **a_str_reply) {
    int ret = -666;
    int arg_index = 1;
    dap_chain_net_t * l_chain_net = NULL;
    dap_chain_t * l_chain = NULL;

    if (dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,a_str_reply,&l_chain,&l_chain_net)) {
        return -3;
    }

    const char * l_datum_hash_str = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-datum", &l_datum_hash_str);
    if (!l_datum_hash_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "Command srv_datum requires parameter '-datum' <datum hash>");
        return -4;
    }

    const char * l_system_datum_folder = dap_config_get_item_str(g_config, "resources", "datum_folder");

    const char * l_datum_cmd_str = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "datum", &l_datum_cmd_str);
    if ( l_datum_cmd_str != NULL ) {
        if ( strcmp(l_datum_cmd_str, "save") == 0) {
            char * l_gdb_group = dap_chain_net_get_gdb_group_mempool(l_chain);
            size_t l_datum_size = 0;

            size_t l_path_length = strlen(l_system_datum_folder)+8+strlen(l_datum_hash_str);
            char *l_path = DAP_NEW_Z_SIZE(char, l_path_length);
            snprintf(l_path, l_path_length, "%s/%s.datum", l_system_datum_folder, l_datum_hash_str);
            
            char * l_file_dir = dap_path_get_dirname(l_path);
            dap_mkdir_with_parents(l_file_dir);
            DAP_DELETE(l_file_dir);

            FILE * l_file = fopen(l_path,"wb");
            if( l_file ){
                size_t l_data_size = 0;
                dap_chain_datum_t* l_datum = (dap_chain_datum_t*)dap_chain_global_db_gr_get(l_datum_hash_str, &l_data_size, l_gdb_group);
                if ( l_datum ){
                    size_t l_retbytes;
                    if ( (l_retbytes = fwrite(l_datum->data, 1, l_datum->header.data_size, l_file)) != l_datum->header.data_size ){
                        log_it(L_ERROR, "Can't write %u bytes on disk (processed only %zu)!", l_datum->header.data_size, l_retbytes);
                        return -3;
                    }
                    fclose(l_file);
                    DAP_DELETE(l_datum);
                    return -5;
                }else{
                    log_it(L_ERROR,"Can't serialize certificate in memory");
                    fclose(l_file);
                    return -4;
                }
            }else{
                log_it(L_ERROR, "Can't open file '%s' for write: %s", l_path, strerror(errno));
                return -2;
            }
        }
        if ( strcmp(l_datum_cmd_str, "load") == 0 ) {

            size_t l_path_length = strlen(l_system_datum_folder)+8+strlen(l_datum_hash_str);
            char *l_path = DAP_NEW_Z_SIZE(char, l_path_length);
            snprintf(l_path, l_path_length, "%s/%s.datum", l_system_datum_folder, l_datum_hash_str);

            size_t l_datum_data_size = 0;
            uint8_t *l_datum_data = dap_chain_net_srv_file_datum_data_read(l_path, &l_datum_data_size);

            char *l_ret;
            if ((l_ret = dap_chain_net_srv_datum_custom_add(l_chain, l_datum_data, l_datum_data_size)) == NULL) {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                        "Can't place datum custom \"%s\" to mempool", l_datum_hash_str);
            }
            else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                        "Datum custom %s was successfully placed to mempool", l_datum_hash_str); 
                DAP_DELETE(l_ret);
                return 0;
            }
        }
    }
    return -1;
}
