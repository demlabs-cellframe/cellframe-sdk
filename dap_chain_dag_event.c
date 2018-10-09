/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net      https://gitlab/demlabs
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

#include "dap_common.h"
#include "dap_chain_dag_event.h"

#define LOG_TAG "chain_dag_event"

/**
 * @brief dap_chain_dag_event_new
 * @param a_dag
 * @param a_datum
 * @return
 */
dap_chain_dag_event_t * dap_chain_dag_event_new(dap_chain_dag_t * a_dag,dap_chain_datum_t * a_datum)
{

}

/**
 * @brief dap_chain_dag_event_delete
 * @param a_dag
 * @param a_event
 */
void dap_chain_dag_event_delete(dap_chain_dag_t * a_dag,dap_chain_dag_event_t * a_event)
{

}

/**
 * @brief dap_chain_dag_event_verify
 * @return
 */
int dap_chain_dag_event_verify(dap_chain_dag_event_t * a_event)
{
    return 0;

}

/**
 * @brief dap_chain_dag_event_get_datum
 * @param a_event
 * @return
 */
dap_chain_datum_t* dap_chain_dag_event_get_datum(dap_chain_dag_event_t * a_event)
{
    uint8_t * l_signs = a_event->hashes_n_signs_n_datum
            +a_event->header.hash_count*sizeof(dap_chain_hash_fast_t);
    uint16_t l_signs_offset = 0;
    uint16_t l_signs_passed;
    for ( l_signs_passed=0;  l_signs_passed < a_event->header.signs_count; l_signs_passed++){
        dap_chain_sign_t * l_sign = (dap_chain_sign_t *) l_signs+l_signs_offset;
        l_signs_offset+=l_sign->header.sign_pkey_size+l_sign->header.sign_size+sizeof(l_sign->header);
    }
    return (dap_chain_datum_t*)  l_signs+l_signs_offset;
}

