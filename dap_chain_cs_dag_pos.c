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
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_pos.h"

#include "dap_chain_ledger.h"

#define LOG_TAG "dap_chain_cs_dag_pos"

typedef struct dap_chain_cs_dag_pos_pvt
{
    char ** tokens_hold;
    uint64_t * tokens_hold_value;
    size_t tokens_hold_size;
} dap_chain_cs_dag_pos_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_pos_pvt_t *) a->_pvt )

static void s_callback_delete(dap_chain_cs_dag_t * a_dag);
static int s_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event);

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
 * @brief s_callback_event_verify
 * @param a_dag
 * @param a_dag_event
 * @return
 */
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event)
{
    dap_chain_cs_dag_pos_t * l_pos =DAP_CHAIN_CS_DAG_POS( a_dag ) ;
    dap_chain_cs_dag_pos_pvt_t * l_pos_pvt = PVT ( DAP_CHAIN_CS_DAG_POS( a_dag ) );

    if(a_dag->chain->ledger == NULL)
        return -3;

    if ( a_dag_event->header.signs_count == 1 ){
        dap_chain_addr_t l_addr;
        dap_chain_sign_t * l_sign = dap_chain_cs_dag_event_get_sign(a_dag_event,0);
        dap_enc_key_t * l_key = dap_chain_sign_to_enc_key( l_sign);

        dap_chain_addr_fill (&l_addr,l_key,&a_dag->chain->net_id );
        dap_enc_key_delete (l_key); // TODO cache all this operations to prevent useless memory copy ops

        for (size_t i =0; i <l_pos_pvt->tokens_hold_size; i++){
            if ( dap_chain_ledger_calc_balance ( a_dag->chain->ledger , &l_addr, l_pos_pvt->tokens_hold[i] ) >= l_pos_pvt->tokens_hold_value[i]  )
                return 0;
        }
        return -1;
    }else
       return -2; // Wrong signatures number
}


