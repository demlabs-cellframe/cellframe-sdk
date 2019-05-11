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
#include <string.h>
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"

#include "dap_chain_cert.h"

#define LOG_TAG "dap_chain_cs_dag_poa"

typedef struct dap_chain_cs_dag_poa_pvt
{
    dap_chain_cert_t ** auth_certs;
    char * auth_certs_prefix;
    uint16_t auth_certs_count;
    uint16_t auth_certs_count_verify; // Number of signatures, needed for event verification
    uint8_t padding[4];
} dap_chain_cs_dag_poa_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_poa_pvt_t *) a->_pvt )

static void s_callback_delete(dap_chain_cs_dag_t * a_dag);
static int s_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event);

// CLI commands
static int s_cli_dag_poa(int argc, const char ** argv, char **str_reply);

/**
 * @brief dap_chain_cs_dag_poa_init
 * @return
 */
int dap_chain_cs_dag_poa_init(void)
{
    // Add consensus constructor
    dap_chain_cs_add ("dag-poa", s_callback_new );

    return 0;
}

/**
 * @brief dap_chain_cs_dag_poa_deinit
 */
void dap_chain_cs_dag_poa_deinit(void)
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
    dap_chain_cs_dag_poa_t * l_poa = DAP_NEW_Z ( dap_chain_cs_dag_poa_t);
    l_dag->_inheritor = l_poa;
    l_dag->callback_delete = s_callback_delete;
    l_dag->callback_cs_verify = s_callback_event_verify;
    l_poa->_pvt = DAP_NEW_Z ( dap_chain_cs_dag_poa_pvt_t );

    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( l_poa );
    if (dap_config_get_item_str(a_chain_cfg,"dag-poa","auth_certs_prefix") ) {
        l_poa_pvt->auth_certs_count = dap_config_get_item_uint16_default(a_chain_cfg,"dag-poa","auth_certs_number",0);
        l_poa_pvt->auth_certs_count_verify = dap_config_get_item_uint16_default(a_chain_cfg,"dag-poa","auth_certs_number_verify",0);
        l_poa_pvt->auth_certs_prefix = strdup ( dap_config_get_item_str(a_chain_cfg,"dag-poa","auth_certs_prefix") );
        if (l_poa_pvt->auth_certs_count && l_poa_pvt->auth_certs_count_verify ) {
            l_poa_pvt->auth_certs = DAP_NEW_Z_SIZE ( dap_chain_cert_t *, l_poa_pvt->auth_certs_count );
            char l_cert_name[512];
            for (size_t i = 0; i < l_poa_pvt->auth_certs_count ; i++ ){
                snprintf(l_cert_name,sizeof(l_cert_name),"%s.%lu",l_poa_pvt->auth_certs_prefix, i);
                if ( l_poa_pvt->auth_certs[i] = dap_chain_cert_find_by_name( l_cert_name) ) {
                    log_it(L_NOTICE, "Initialized auth cert \"%s\"", l_cert_name);
                } else{
                    log_it(L_ERROR, "Can't find cert \"%s\"", l_cert_name);
                    return -1;
                }
            }
        }
    }
    log_it(L_NOTICE,"Initialized DAG-PoA consensus with %u/%u minimum consensus",l_poa_pvt->auth_certs_count,l_poa_pvt->auth_certs_count_verify);
    return 0;
}

/**
 * @brief s_chain_cs_dag_callback_delete
 * @param a_dag
 */
static void s_callback_delete(dap_chain_cs_dag_t * a_dag)
{
    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA ( a_dag );

    if ( l_poa->_pvt ) {
        dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( l_poa );

        if ( l_poa_pvt->auth_certs )
            DAP_DELETE ( l_poa_pvt->auth_certs);

        if ( l_poa_pvt->auth_certs_prefix )
            free ( l_poa_pvt->auth_certs_prefix );

        DAP_DELETE ( l_poa->_pvt);
    }

    if ( l_poa->_inheritor ) {
       DAP_DELETE ( l_poa->_inheritor );
    }
}



/**
 * @brief s_chain_cs_dag_callback_event_verify
 * @param a_dag
 * @param a_dag_event
 * @return
 */
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event)
{
    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( DAP_CHAIN_CS_DAG_POA( a_dag ) );
    if ( a_dag_event->header.signs_count >= l_poa_pvt->auth_certs_count_verify ){
        size_t l_verified = 0;
        for ( uint16_t i = 0; i < a_dag_event->header.signs_count; i++ ){
            for ( uint16_t j = 0; j < l_poa_pvt->auth_certs_count; j++){
                if( dap_chain_cert_compare_with_sign ( l_poa_pvt->auth_certs[j],
                            dap_chain_cs_dag_event_get_sign(a_dag_event,i) ) == 0 )
                    l_verified++;
            }
        }
        return l_verified >= l_poa_pvt->auth_certs_count_verify ? 0 : -1;
    }else
       return -2; // Wrong signatures number
}

