/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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
#include <stdlib.h>

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_chain_net.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_pos.h"
#include "dap_chain_net_srv_stake.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "dap_chain_cs_dag_pos"

typedef struct dap_chain_cs_dag_pos_pvt
{
    dap_cert_t * events_sign_wallet;
    char ** tokens_hold;
    uint64_t * tokens_hold_value;
    size_t tokens_hold_size;
    uint16_t confirmations_minimum;
} dap_chain_cs_dag_pos_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_pos_pvt_t *) a->_pvt )

static void s_callback_delete(dap_chain_cs_dag_t * a_dag);
static int s_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);
static int s_callback_created(dap_chain_t * a_chain, dap_config_t *a_chain_cfg);
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event, size_t a_dag_event_size);
static dap_chain_cs_dag_event_t * s_callback_event_create(dap_chain_cs_dag_t * a_dag, dap_chain_datum_t * a_datum,
                                                          dap_chain_hash_fast_t * a_hashes, size_t a_hashes_count, size_t *a_dag_event_size);

/**
 * @brief dap_chain_cs_dag_pos_init
 * @return
 */
int dap_chain_cs_dag_pos_init()
{
    dap_chain_cs_add ("dag_pos", s_callback_new );
    return 0;
}

/**
 * @brief dap_chain_cs_dag_pos_deinit
 */
void dap_chain_cs_dag_pos_deinit(void)
{

}

/**
 * @brief s_cs_callback
 * @param a_chain
 * @param a_chain_cfg
 */
static int s_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_cs_dag_new(a_chain,a_chain_cfg);
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG ( a_chain );
    dap_chain_cs_dag_pos_t * l_pos = DAP_NEW_Z ( dap_chain_cs_dag_pos_t);
    l_dag->_inheritor = l_pos;
    l_dag->callback_delete = s_callback_delete;
    l_dag->callback_cs_verify = s_callback_event_verify;
    l_dag->callback_cs_event_create = s_callback_event_create;
    l_pos->_pvt = DAP_NEW_Z ( dap_chain_cs_dag_pos_pvt_t );

    dap_chain_cs_dag_pos_pvt_t * l_pos_pvt = PVT ( l_pos );

    char ** l_tokens_hold = NULL;
    char ** l_tokens_hold_value_str = NULL;
    uint16_t l_tokens_hold_size = 0;
    uint16_t l_tokens_hold_value_size = 0;

    l_tokens_hold = dap_config_get_array_str( a_chain_cfg,"dag-pos","tokens_hold",&l_tokens_hold_size);
    l_tokens_hold_value_str = dap_config_get_array_str( a_chain_cfg,"dag-pos","tokens_hold_value",&l_tokens_hold_value_size);

    if ( l_tokens_hold_size != l_tokens_hold_value_size ){
        log_it(L_CRITICAL, "tokens_hold and tokens_hold_value are different size!");
        goto lb_err;
    }
    l_pos_pvt->confirmations_minimum = dap_config_get_item_uint16_default( a_chain_cfg,"dag-pos","confirmations_minimum",1);
    l_pos_pvt->tokens_hold_size = l_tokens_hold_size;
    l_pos_pvt->tokens_hold = DAP_NEW_Z_SIZE( char*, sizeof(char*) *
                                             l_tokens_hold_size );

    l_pos_pvt->tokens_hold_value = DAP_NEW_Z_SIZE(uint64_t,
                                                  (l_tokens_hold_value_size +1) *sizeof (uint64_t));

    for (size_t i = 0; i < l_tokens_hold_value_size; i++){
        l_pos_pvt->tokens_hold[i] = dap_strdup( l_tokens_hold[i] );
        if ( ( l_pos_pvt->tokens_hold_value[i] =
               strtoull(l_tokens_hold_value_str[i],NULL,10) ) == 0 ) {
             log_it(L_CRITICAL, "Token %s has inproper hold value \"%s\"",l_pos_pvt->tokens_hold[i],
                    l_pos_pvt->tokens_hold_value[i] );
             goto lb_err;
        }
    }
    l_dag->chain->callback_created = s_callback_created;
    return 0;

lb_err:
    for (int i = 0; i < l_tokens_hold_size; i++ )
        DAP_DELETE(l_tokens_hold[i]);
    DAP_DELETE(l_tokens_hold);
    DAP_DELETE( l_pos_pvt->tokens_hold_value);
    DAP_DELETE( l_pos_pvt);
    DAP_DELETE(l_pos );
    l_dag->_inheritor = NULL;
    l_dag->callback_delete = NULL;
    l_dag->callback_cs_verify = NULL;
    return -1;

}

/**
 * @brief s_callback_created
 * @param a_chain
 * @param a_chain_cfg
 * @return
 */
static int s_callback_created(dap_chain_t * a_chain, dap_config_t *a_chain_net_cfg)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG ( a_chain );
    dap_chain_cs_dag_pos_t * l_pos = DAP_CHAIN_CS_DAG_POS( l_dag );

    const char * l_events_sign_wallet = NULL;
    if ( ( l_events_sign_wallet = dap_config_get_item_str(a_chain_net_cfg,"dag-pos","events-sign-wallet") ) != NULL ) {

        if ( ( PVT(l_pos)->events_sign_wallet = dap_cert_find_by_name(l_events_sign_wallet)) == NULL ){
            log_it(L_ERROR,"Can't load events sign certificate, name \"%s\" is wrong",l_events_sign_wallet);
        }else
            log_it(L_NOTICE,"Loaded \"%s\" certificate to sign pos event", l_events_sign_wallet);

    }
    return 0;
}


/**
 * @brief s_chain_cs_dag_callback_delete
 * @param a_dag
 */
static void s_callback_delete(dap_chain_cs_dag_t * a_dag)
{
    dap_chain_cs_dag_pos_t * l_pos = DAP_CHAIN_CS_DAG_POS ( a_dag );

    if ( l_pos->_pvt ) {
        dap_chain_cs_dag_pos_pvt_t * l_pos_pvt = PVT ( l_pos );
        DAP_DELETE ( l_pos_pvt);
    }

    if ( l_pos->_inheritor ) {
       DAP_DELETE ( l_pos->_inheritor );
    }
}

/**
 * @brief s_callback_event_create
 * @param a_dag
 * @param a_datum
 * @param a_hashes
 * @param a_hashes_count
 * @return
 */
static dap_chain_cs_dag_event_t * s_callback_event_create(dap_chain_cs_dag_t * a_dag, dap_chain_datum_t * a_datum,
                                                          dap_chain_hash_fast_t * a_hashes, size_t a_hashes_count,
                                                          size_t *a_dag_event_size)
{
    dap_return_val_if_fail(a_dag && a_dag->chain && DAP_CHAIN_CS_DAG_POS(a_dag) && a_datum, NULL);
    dap_chain_net_t * l_net = dap_chain_net_by_name( a_dag->chain->net_name );
    dap_chain_cs_dag_pos_t * l_pos = DAP_CHAIN_CS_DAG_POS(a_dag);

    if( PVT(l_pos)->events_sign_wallet == NULL) {
        log_it(L_ERROR, "Can't sign event with events-sign-wallet in [dag-pos] section");
        return NULL;
    }
    if(a_datum || (a_hashes && a_hashes_count)) {
        dap_chain_cs_dag_event_t * l_event = dap_chain_cs_dag_event_new(a_dag->chain->id, l_net->pub.cell_id, a_datum,
        PVT(l_pos)->events_sign_wallet->enc_key, a_hashes, a_hashes_count, a_dag_event_size);
        return l_event;
    } else
        return NULL;
}

/**
 * @brief s_callback_event_verify
 * @param a_dag
 * @param a_dag_event
 * @return
 */
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event, size_t a_dag_event_size)
{

    dap_chain_cs_dag_pos_t * l_pos =DAP_CHAIN_CS_DAG_POS( a_dag ) ;
    dap_chain_cs_dag_pos_pvt_t * l_pos_pvt = PVT ( DAP_CHAIN_CS_DAG_POS( a_dag ) );

    if(a_dag->chain->ledger == NULL){
        log_it(L_CRITICAL,"Ledger is NULL can't check PoS on this chain %s", a_dag->chain->name);
        return -3;
    }

    if (sizeof (a_dag_event->header)>= a_dag_event_size){
        log_it(L_WARNING,"Incorrect size with event %p on chain %s", a_dag_event, a_dag->chain->name);
        return  -7;
    }
    if ( a_dag_event->header.signs_count >= l_pos_pvt->confirmations_minimum ){
        uint16_t l_verified_num = 0;
        dap_chain_addr_t l_addr = { 0 };

        for ( size_t l_sig_pos=0; l_sig_pos < a_dag_event->header.signs_count; l_sig_pos++ ){
            dap_sign_t * l_sign = dap_chain_cs_dag_event_get_sign(a_dag_event, a_dag_event_size,l_sig_pos);
            if ( l_sign == NULL){
                log_it(L_WARNING, "Event is NOT signed with anything: sig pos %zd, event size %zd", a_dag_event_size);
                return -4;
            }
            size_t l_dag_event_size_without_sign = dap_chain_cs_dag_event_calc_size_excl_signs(a_dag_event,a_dag_event_size);

            bool l_sign_verify_ret = dap_sign_verify_size(l_sign, a_dag_event_size) &&
                    dap_sign_verify(l_sign,a_dag_event,l_dag_event_size_without_sign) == 0;
            if ( !l_sign_verify_ret ){
                log_it(L_WARNING, "Event's sign is incorrect: code %d", l_sign_verify_ret);
                return -41;

            }

            if (!l_dag_event_size_without_sign){
                log_it(L_WARNING,"Event has nothing except sign, nothing to verify so I pass it (who knows why we have it?)");
                return 0;
            }

            dap_chain_hash_fast_t l_pkey_hash;
            if (!dap_sign_get_pkey_hash(l_sign, &l_pkey_hash)) {
                log_it(L_WARNING, "Event's sign has no any key");
                return -5;
            }
            dap_chain_addr_fill(&l_addr, l_sign->header.type, &l_pkey_hash, a_dag->chain->net_id);



            if (l_sig_pos == 0) {
                dap_chain_datum_t *l_datum = (dap_chain_datum_t *)dap_chain_cs_dag_event_get_datum(a_dag_event,a_dag_event_size);
                if (l_datum->header.type_id == DAP_CHAIN_DATUM_TX) {
                    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
                    if (!dap_chain_net_srv_stake_validator(&l_addr, l_tx)) {
                        log_it(L_WARNING,"Not passed stake validator with event %p on chain %s", a_dag_event, a_dag->chain->name);
                        return -6;
                    }
                }
            }
            /*
            dap_chain_datum_t *l_datum = dap_chain_cs_dag_event_get_datum(a_dag_event);
            // transaction include emission?
            bool l_is_emit = false;
            if(l_datum && l_datum->header.type_id == DAP_CHAIN_DATUM_TX) {
                // transaction
                dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;
                // find Token items
                dap_list_t *l_list_tx_token = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_TOKEN, NULL);
                if(l_list_tx_token)
                    l_is_emit = true;
                dap_list_free(l_list_tx_token);
            }
            // if emission then the wallet can be with zero balance
            if(l_is_emit)
                return 0;*/

            bool l_is_enough_balance = false;
            for (size_t i =0; i <l_pos_pvt->tokens_hold_size; i++){
                uint128_t l_balance = dap_chain_ledger_calc_balance ( a_dag->chain->ledger , &l_addr, l_pos_pvt->tokens_hold[i] );
                uint64_t l_value = dap_chain_uint128_to(l_balance);
                if (l_value >= l_pos_pvt->tokens_hold_value[i]) {
                    l_verified_num++;
                    l_is_enough_balance = true;
                    break;
                }
            }
            if (! l_is_enough_balance ){
                char *l_addr_str = dap_chain_addr_to_str(&l_addr);
                log_it(L_WARNING, "Verify of event is false, because bal is not enough for addr=%s", l_addr_str);
                DAP_DELETE(l_addr_str);
                return -1;
            }
        }

        // Check number
        if ( l_verified_num >= l_pos_pvt->confirmations_minimum ){
            // Passed all checks
            return 0;
        }else{
            log_it(L_WARNING, "Wrong event: only %su/%su signs are valid", l_verified_num, l_pos_pvt->confirmations_minimum );
            return -2;
        }
    }else{
        log_it(L_WARNING,"Wrong signature number with event %p on chain %s", a_dag_event, a_dag->chain->name);
        return -2; // Wrong signatures number
    }
}
