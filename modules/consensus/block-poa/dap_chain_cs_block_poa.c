/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Limited https://demlabs.net
 * DAP SDK          https://gitlab.demlabs.net/dap/dap-sdk
 * Copyright  (c) 2017
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dap_chain_net.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_enc_base58.h"
#include "dap_cert.h"
#include "dap_chain.h"
#include "dap_chain_pvt.h"
#include "dap_chain_block.h"
#include "dap_chain_block_cache.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_cs_block_poa.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_global_db.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_net_srv_stake.h"

#define LOG_TAG "dap_chain_cs_block_poa"


typedef struct dap_chain_cs_dag_poa_pvt
{
    dap_enc_key_t *sign_key;
    dap_cert_t ** auth_certs;
    char * auth_certs_prefix;
    uint16_t auth_certs_count;
    uint16_t auth_certs_count_verify; // Number of signatures, needed for event verification

    dap_chain_callback_new_cfg_t prev_callback_created; // global network config init
} dap_chain_cs_block_poa_pvt_t;

#define PVT(a) ((dap_chain_cs_block_poa_pvt_t *) a->_pvt )

static void s_callback_delete(dap_chain_cs_blocks_t* a_blocks);
static int s_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);
static int s_callback_created(dap_chain_t * a_chain, dap_config_t *a_chain_cfg);
static int s_callback_block_verify(dap_chain_cs_blocks_t * a_blocks, dap_chain_block_t* a_block, size_t a_block_size);
static size_t s_callback_block_sign(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t **a_block_ptr, size_t a_block_size);

// CLI commands
static int s_cli_block_poa(int argc, char ** argv, char **str_reply);

static bool s_seed_mode = false;
/**
 * @brief dap_chain_cs_block_poa_init
 * @return
 */
int dap_chain_cs_block_poa_init(void)
{
    // Add consensus constructor
    dap_chain_cs_add ("block_poa", s_callback_new );
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    dap_chain_node_cli_cmd_item_create ("block_poa", s_cli_block_poa, "Blockchain PoA commands",
        "block_poa -net <chain net name> -chain <chain name> block sign [-cert <cert name>] \n"
            "\tSign new block with certificate <cert name> or withs own PoA certificate\n\n");

    return 0;
}

/**
 * @brief dap_chain_cs_block_poa_deinit
 */
void dap_chain_cs_block_poa_deinit(void)
{

}



/**
 * @brief s_cli_block_poa
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
static int s_cli_block_poa(int argc, char ** argv, char **a_str_reply)
{
    int ret = -666;
    int arg_index = 1;
    dap_chain_net_t * l_chain_net = NULL;
    dap_chain_t * l_chain = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,a_str_reply,&l_chain,&l_chain_net);

    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);
    dap_chain_cs_block_poa_pvt_t * l_poa_pvt = PVT ( DAP_CHAIN_CS_BLOCK_POA( l_blocks ) );

    const char * l_block_new_cmd_str = NULL;
    const char * l_block_hash_str = NULL;
    const char * l_cert_str = NULL;

    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "block", &l_block_new_cmd_str);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-block", &l_block_hash_str);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-cert", &l_cert_str);

    dap_enc_key_t *l_sign_key;
    // Load cert to sign if its present
    if (l_cert_str) {
        dap_cert_t *l_cert = dap_cert_find_by_name( l_cert_str);
        l_sign_key = l_cert->enc_key;
    } else {
        l_sign_key = l_poa_pvt->sign_key;
    }
    if (!l_sign_key || !l_sign_key->priv_key_data) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "No certificate to sign blocks\n");
        return -2;
    }

    // block hash may be in hex or base58 format
    char *l_block_hash_hex_str;
    char *l_event_hash_base58_str;
    if(!dap_strncmp(l_block_hash_str, "0x", 2) || !dap_strncmp(l_block_hash_str, "0X", 2)) {
        l_block_hash_hex_str = dap_strdup(l_block_hash_str);
        l_event_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_block_hash_str);
    }
    else {
        l_block_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_block_hash_str);
        l_event_hash_base58_str = dap_strdup(l_block_hash_str);
    }

    // Parse block cmd
    if ( l_block_new_cmd_str != NULL ){
        if ( strcmp(l_block_new_cmd_str,"sign") == 0) { // Sign event command
                l_blocks->block_new_size = dap_chain_block_sign_add( &l_blocks->block_new,l_blocks->block_new_size, l_sign_key);
                //dap_chain_hash_fast_t l_block_new_hash;
                //dap_hash_fast(l_blocks->block_new, l_blocks->block_new_size,&l_block_new_hash);
        }
    }
    return ret;
}

/**
 * @brief s_cs_callback
 * @param a_chain
 * @param a_chain_cfg
 */
static int s_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_cs_blocks_new(a_chain, a_chain_cfg);
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS( a_chain );
    dap_chain_cs_block_poa_t * l_poa = DAP_NEW_Z ( dap_chain_cs_block_poa_t);
    l_blocks->_inheritor = l_poa;
    l_blocks->callback_delete = s_callback_delete;
    l_blocks->callback_block_verify = s_callback_block_verify;
    l_blocks->callback_block_sign = s_callback_block_sign;
    l_poa->_pvt = DAP_NEW_Z(dap_chain_cs_block_poa_pvt_t);
    dap_chain_cs_block_poa_pvt_t *l_poa_pvt = PVT(l_poa);

    if (dap_config_get_item_str(a_chain_cfg,"block-poa","auth_certs_prefix") ) {
        l_poa_pvt->auth_certs_count = dap_config_get_item_uint16_default(a_chain_cfg,"block-poa","auth_certs_number",0);
        l_poa_pvt->auth_certs_count_verify = dap_config_get_item_uint16_default(a_chain_cfg,"block-poa","auth_certs_number_verify",0);
        l_poa_pvt->auth_certs_prefix = strdup ( dap_config_get_item_str(a_chain_cfg,"block-poa","auth_certs_prefix") );
        if (l_poa_pvt->auth_certs_count && l_poa_pvt->auth_certs_count_verify ) {
            // Type sizeof's misunderstanding in malloc?
            l_poa_pvt->auth_certs = DAP_NEW_Z_SIZE ( dap_cert_t *, l_poa_pvt->auth_certs_count * sizeof(dap_cert_t));
            char l_cert_name[512];
            for (size_t i = 0; i < l_poa_pvt->auth_certs_count ; i++ ){
                dap_snprintf(l_cert_name,sizeof(l_cert_name),"%s.%zu",l_poa_pvt->auth_certs_prefix, i);
                if ((l_poa_pvt->auth_certs[i] = dap_cert_find_by_name( l_cert_name)) == NULL) {
                    dap_snprintf(l_cert_name,sizeof(l_cert_name),"%s.%zu.pub",l_poa_pvt->auth_certs_prefix, i);
                    if ((l_poa_pvt->auth_certs[i] = dap_cert_find_by_name( l_cert_name)) == NULL) {
                        log_it(L_ERROR, "Can't find cert \"%s\"", l_cert_name);
                        return -1;
                    }
                }
                log_it(L_NOTICE, "Initialized auth cert \"%s\"", l_cert_name);
            }
        }
    }
    log_it(L_NOTICE,"Initialized Block-PoA consensus with %u/%u minimum consensus",l_poa_pvt->auth_certs_count,l_poa_pvt->auth_certs_count_verify);
    // Save old callback if present and set the call of its own (chain callbacks)
    l_poa_pvt->prev_callback_created = l_blocks->chain->callback_created;
    l_blocks->chain->callback_created = s_callback_created;
    return 0;
}

/**
 * @brief s_callback_created
 * @param a_chain
 * @param a_chain_cfg
 * @return
 */
static int s_callback_created(dap_chain_t * a_chain, dap_config_t *a_chain_net_cfg)
{
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS( a_chain );
    dap_chain_cs_block_poa_t * l_poa = DAP_CHAIN_CS_BLOCK_POA( l_blocks );

    // Call previous callback if present. So the first called is the first in
    if (PVT(l_poa)->prev_callback_created )
        PVT(l_poa)->prev_callback_created(a_chain,a_chain_net_cfg);

    const char * l_sign_cert_str = NULL;
    if ( ( l_sign_cert_str = dap_config_get_item_str(a_chain_net_cfg,"block-poa","blocks-sign-cert") ) != NULL ) {
        dap_cert_t *l_sign_cert = dap_cert_find_by_name(l_sign_cert_str);
        if (l_sign_cert == NULL) {
            log_it(L_ERROR, "Can't load sign certificate, name \"%s\" is wrong", l_sign_cert_str);
        } else if (l_sign_cert->enc_key->priv_key_data) {
            PVT(l_poa)->sign_key = l_sign_cert->enc_key;
            log_it(L_NOTICE, "Loaded \"%s\" certificate to sign poa blocks", l_sign_cert_str);
        } else {
            log_it(L_ERROR, "Certificate \"%s\" has no private key", l_sign_cert_str);
        }
    } else {
        log_it(L_ERROR, "No sign certificate provided, can't sign any blocks");
    }
    return 0;
}

/**
 * @brief s_chain_cs_dag_callback_delete
 * @param a_dag
 */
static void s_callback_delete(dap_chain_cs_blocks_t * a_blocks)
{
    dap_chain_cs_block_poa_t * l_poa = DAP_CHAIN_CS_BLOCK_POA ( a_blocks );

    if ( l_poa->_pvt ) {
        dap_chain_cs_block_poa_pvt_t * l_poa_pvt = PVT ( l_poa );

        if ( l_poa_pvt->auth_certs )
            DAP_DELETE ( l_poa_pvt->auth_certs);

        if ( l_poa_pvt->auth_certs_prefix )
            DAP_DELETE( l_poa_pvt->auth_certs_prefix );

        DAP_DELETE ( l_poa->_pvt);
    }

    if ( l_poa->_inheritor ) {
       DAP_DELETE ( l_poa->_inheritor );
    }
}

/**
 * @brief
 * function makes block singing
 * @param a_dag a_blocks dap_chain_cs_blocks_t
 * @param a_block dap_chain_block_t
 * @param a_block_size size_t size of block object
 * @return int
 */
static size_t s_callback_block_sign(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t **a_block_ptr, size_t a_block_size)
{
    assert(a_blocks);
    dap_chain_cs_block_poa_t *l_poa = DAP_CHAIN_CS_BLOCK_POA(a_blocks);
    dap_chain_cs_block_poa_pvt_t *l_poa_pvt = PVT(l_poa);
    if (!l_poa_pvt->sign_key) {
        log_it(L_WARNING, "Can't sign block with blocks-sign-cert in [block-poa] section");
        return 0;
    }
    if (!a_block_ptr || !(*a_block_ptr) || !a_block_size) {
        log_it(L_WARNING, "Block size or block pointer is NULL");
        return 0;
    }
    return dap_chain_block_sign_add(a_block_ptr, a_block_size, l_poa_pvt->sign_key);
}

/**
 * @brief s_callbac_block_verify
 * @param a_blocks
 * @param a_block
 * @param a_block_size
 * @return
 */
static int s_callback_block_verify(dap_chain_cs_blocks_t * a_blocks, dap_chain_block_t * a_block, size_t a_block_size)
{
    dap_chain_cs_block_poa_pvt_t * l_poa_pvt = PVT ( DAP_CHAIN_CS_BLOCK_POA( a_blocks ) );
    uint16_t l_signs_verified_count = 0;

    // Check for first signature
    dap_sign_t * l_sign = dap_chain_block_sign_get(a_block,a_block_size,0);
    if (! l_sign){
        log_it(L_ERROR, "No any signatures at all for block");
        return -2;
    }
    // Parse the rest signs
    size_t l_offset = (byte_t *)l_sign - a_block->meta_n_datum_n_sign;
    while (l_offset < a_block_size - sizeof(a_block->hdr)) {
        if (!dap_sign_verify_size(l_sign, a_block_size)) {
            log_it(L_ERROR, "Corrupted block: sign size is bigger than block size");
            return -3;
        }
        size_t l_sign_size = dap_sign_get_size(l_sign);
        // Check if sign size 0
        if (!l_sign_size){
            log_it(L_ERROR, "Corrupted block: sign size got zero");
            return -4;
        }
        // Check if sign size too big
        if (l_sign_size > a_block_size- sizeof (a_block->hdr)-l_offset ){
            log_it(L_ERROR, "Corrupted block: sign size %zd is too big, out from block size %zd", l_sign_size, a_block_size);
            return -5;
        }
        // Compare signature with auth_certs
        for (uint16_t j = 0; j < l_poa_pvt->auth_certs_count; j++) {
            if (dap_cert_compare_with_sign ( l_poa_pvt->auth_certs[j], l_sign) == 0){
                l_signs_verified_count++;
                break;
            }
        }
        //TODO verify sign itself
        l_offset += l_sign_size;
        l_sign = (dap_sign_t *)(a_block->meta_n_datum_n_sign + l_offset);
    }
    if (l_offset != a_block_size - sizeof(a_block->hdr)) {
        log_it(L_ERROR, "Corrupted block: sign end exceeded the block bound");
        return -6;
    }
    return l_signs_verified_count >= l_poa_pvt->auth_certs_count_verify ? 0 : -1;
}

dap_cert_t **dap_chain_cs_block_poa_get_auth_certs(dap_chain_t *a_chain, size_t *a_auth_certs_count)
{
    dap_chain_pvt_t *l_chain_pvt = DAP_CHAIN_PVT(a_chain);
    if (strcmp(l_chain_pvt->cs_name, "block_poa"))
        return NULL;
    dap_chain_cs_block_poa_pvt_t *l_poa_pvt = PVT(DAP_CHAIN_CS_BLOCK_POA(DAP_CHAIN_CS_BLOCKS(a_chain)));
    if (a_auth_certs_count)
        *a_auth_certs_count = l_poa_pvt->auth_certs_count;
    return l_poa_pvt->auth_certs;
}
