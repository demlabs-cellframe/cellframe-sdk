/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
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

#include <stdint.h>
#include "dap_strfuncs.h"
#include "rand/dap_rand.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_stream.h"
#include "dap_server_http_db_auth.h"
#include "dap_chain_net_srv_common.h"

/**
 * copy a_value_dst to a_uid_src
 */
void dap_chain_net_srv_uid_set(dap_chain_net_srv_uid_t *a_uid_src, uint128_t a_value_dst)
{
    memset(a_uid_src->raw, 0, sizeof(a_uid_src->raw));
    memcpy(a_uid_src->raw, &a_value_dst, min(sizeof(a_uid_src->raw), sizeof(uint128_t)));
}

/**
 * Generate unique id for service
 */
bool dap_chain_net_srv_gen_uid(uint8_t *a_srv, size_t a_srv_size)
{
    if(!a_srv)
        return false;
    randombytes(a_srv, a_srv_size);
    return true;
}

/**
 *  Initialize dap_chain_net_srv_abstract_t structure
 */
void dap_chain_net_srv_abstract_set(dap_chain_net_srv_abstract_t *a_cond, uint8_t a_class, uint128_t a_type_id,
        uint64_t a_price, uint8_t a_price_units, const char *a_decription)
{
    memset(a_cond, 0, sizeof(dap_chain_net_srv_abstract_t));
    // generate unique proposal_id
    dap_chain_net_srv_gen_uid((uint8_t*) &a_cond->proposal_id, sizeof(a_cond->proposal_id));
    // fill structure
    a_cond->class = a_class;
    dap_chain_net_srv_uid_set(&a_cond->type_id, a_type_id);
    a_cond->price = a_price;
    a_cond->price_units = a_price_units;
    if(a_decription)
        strncpy(a_cond->decription, a_decription, sizeof(a_cond->decription) - 1);
}

/**
 *
 */
uint64_t dap_chain_net_srv_client_auth(dap_ledger_t  *a_ledger,
        const char *a_service_key, const dap_chain_net_srv_abstract_t **a_cond_out)
{
    char *l_addr_base58;
    char *l_sign_hash_str;
    if(dap_server_http_db_auth_parse_service_key(a_service_key, &l_addr_base58, &l_sign_hash_str)) {
        return 0;
    }
    if(!dap_server_http_db_auth_check_key(l_addr_base58, l_sign_hash_str)) {
        // invalid signature
        return 0;
    }

    dap_chain_addr_t *l_addr = (l_addr_base58) ? dap_chain_addr_from_str(l_addr_base58) : NULL;
    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    dap_chain_sign_type_t l_sig_type;
    if(l_addr)
        memcpy(&l_sig_type, &l_addr->sig_type, sizeof(dap_chain_sign_type_t));

    // Search all value in transactions with l_addr in 'out_cond' item
    uint64_t l_value = dap_chain_ledger_tx_cache_get_out_cond_value(a_ledger, l_addr, &l_tx_out_cond);
    DAP_DELETE(l_addr);
    // not found transaction with l_addr in 'out_cond' item
    if(!l_value)
        return 0;

    size_t l_pkey_size = 0;
    size_t l_cond_size = 0;
    uint8_t *l_cond = dap_chain_datum_tx_out_cond_item_get_cond(l_tx_out_cond, &l_cond_size);
    uint8_t *l_pkey = dap_chain_datum_tx_out_cond_item_get_pkey(l_tx_out_cond, &l_pkey_size);

    if(l_cond_size != sizeof(dap_chain_net_srv_abstract_t)) {
        return 0;
    }
    if(a_cond_out)
        *a_cond_out = (const dap_chain_net_srv_abstract_t*) l_cond;
    return l_value;
}

// callback for traffic
void dap_chain_net_srv_traffic_callback(dap_server_t *a_server)
{
    pthread_mutex_lock(&a_server->mutex_on_hash);
    dap_client_remote_t *l_client = a_server->clients;
    if(l_client) {
        dap_stream_t *l_stream = DAP_STREAM(l_client);
        if(l_stream)
            for(int i = 0; i < l_stream->channel_count; i++) {
                dap_stream_ch_t * ch = l_stream->channel[i];
                dap_chain_net_srv_t *net_srv = (dap_chain_net_srv_t*) (ch->internal);
                // callback for service
                if(net_srv && net_srv->callback_trafic)
                    net_srv->callback_trafic(l_client, ch);
            }
    }
    pthread_mutex_unlock(&a_server->mutex_on_hash);
}

