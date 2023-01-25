/*
 *
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <memory.h>
#include <assert.h>
#include "dap_common.h"
#include "dap_sign.h"
#include "dap_cert.h"
#include "dap_pkey.h"
#include "dap_chain_net.h"
#include "dap_chain_net_decree.h"
#include "dap_chain_net_srv.h"

#define LOG_TAG "chain_net_decree"

typedef struct dap_chain_net_decree_keys{
    dap_pkey_t key;
    dap_chain_net_decree_keys_t* next;
}   dap_chain_net_decree_keys_t;

static bool dap_chain_datum_decree_find_pkey_in_db (dap_enc_key_t *a_key, dap_chain_t *a_chain)
{
    size_t l_auth_certs_count = 0;
    dap_cert_t *l_serts = NULL;

    // get all auth cert
//    l_serts = (a_chain, &l_auth_certs_count);


    return true;
}

int dap_chain_net_decree_load(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain)
{
    dap_chain_datum_decree_t *l_decree = a_decree;
    // 1. get pkeys sign from decree datum
    size_t sign_max_size = 0;
    //TODO: multiple signs reading from datum
    dap_sign_t *l_sign = dap_chain_datum_decree_get_sign(l_decree, &sign_max_size);
    if (!l_sign)
    {
        log_it(L_WARNING,"Decree data sign not found");
        return -100;
    }
    dap_enc_key_t * l_key = dap_sign_to_enc_key(l_sign);
    //TODO: find unique pkeys in pkeys set from previous step and check that number of signs > min

    // 2. find pkeys in storage
    if (dap_chain_datum_decree_find_pkey_in_db(l_key, a_chain))
    {
        log_it(L_WARNING,"Pub key is invalid");
        return -101;
    }

    //TODO: check all pkeys is in storage

    // 3. verify signs
    size_t l_verify_data_size = l_decree->header.tsd_size + sizeof(dap_chain_datum_decree_t) - sign_max_size;
    if(dap_sign_verify_all(l_sign, sign_max_size, l_decree, l_verify_data_size))
    {
        log_it(L_WARNING,"Decree data sign verify failed");
        return -102;
    }

    switch(l_decree->header.type){
        case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:{

            break;
        }
        case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:{
//            size_t l_datum_data_size = ;
//            dap_chain_net_srv_t * l_srv = dap_chain_net_srv_get(l_decree->header.srv_id);
//            if(l_srv){
//                if(l_srv->callbacks.decree){
//                    dap_chain_net_t * l_net = dap_chain_net_by_id(a_chain->net_id);
//                    l_srv->callbacks.decree(l_srv,l_net,a_chain,l_decree,l_datum_data_size);
//                 }
//            }else{
//                log_it(L_WARNING,"Decree for unknown srv uid 0x%016"DAP_UINT64_FORMAT_X , l_decree->header.srv_id.uint64);
//                return -103;
//            }
        }
        default:;
    }

    return 0;
}
