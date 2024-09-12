/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
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

#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include "dap_chain_net.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_sig.h"
#include "dap_list.h"
#include "dap_sign.h"
#include "dap_time.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_ledger.h"
#include "dap_chain_node_cli.h"
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_math_ops.h"
#include "dap_string.h"
#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_datum_decree.h"
#include "dap_tsd.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_bridge.h"
#include "uthash.h"

#define LOG_TAG "dap_chain_net_srv_bridge"


static inline int s_tsd_str_cmp(const byte_t *a_tsdata, size_t a_tsdsize,  const char *str ) {
    size_t l_strlen = (size_t)strlen(str);
    if (l_strlen != a_tsdsize) return -1;
    return memcmp(a_tsdata, str, l_strlen);
}

//emission tags
//inherits from emission tsd section for engine-produced auth emissions
bool s_get_ems_bridge_action(dap_chain_datum_token_emission_t *a_ems, dap_chain_tx_tag_action_type_t *a_action)
{
    if (!a_ems || !a_action)
        return false;

    if (a_action)
        *a_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;

    size_t src_tsd_size = 0;
    
    src_tsd_size = 0;
    size_t subsrc_tsd_size = 0;
    
    byte_t *ems_src = dap_chain_emission_get_tsd(a_ems, DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_SOURCE, &src_tsd_size);
    byte_t *ems_subsrc = dap_chain_emission_get_tsd(a_ems, DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_SOURCE_SUBTYPE, &subsrc_tsd_size);

    if (ems_src && src_tsd_size)
    {   
        //old bridge ems
        if (s_tsd_str_cmp(ems_src, src_tsd_size, DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_BRIDGE_COMMISSION_OLD) == 0)
        {
            *a_action =  DAP_CHAIN_TX_TAG_ACTION_TRANSFER_COMISSION;
            return true;      
        }
        
        //not bridge
        if (s_tsd_str_cmp(ems_src, src_tsd_size, DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_BRIDGE) != 0)
            return false;
    }
    else
    {
        //special case for old bridge datums
        //no SOURCE, but have all this
        //if emission has 5, 8, 6 section (it's enough) -> this is old bridge tx
        if (dap_chain_emission_get_tsd(a_ems, DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_NET_ID, &src_tsd_size) &&
            dap_chain_emission_get_tsd(a_ems, DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_BLOCK_NUM, &src_tsd_size) &&
            dap_chain_emission_get_tsd(a_ems, DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_OUTER_TX_HASH, &src_tsd_size))
        {
            *a_action = DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REGULAR;
            return true;
        }
    }

    if (ems_subsrc && subsrc_tsd_size)
    {
        if (s_tsd_str_cmp(ems_subsrc, subsrc_tsd_size, DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_BRIDGE_COMMISSION)==0)
        {
            *a_action =  DAP_CHAIN_TX_TAG_ACTION_TRANSFER_COMISSION;
            return true;
        }

        if (s_tsd_str_cmp(ems_subsrc, subsrc_tsd_size, DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_BRIDGE_TRANSFER)==0)
        {
            *a_action =  DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REGULAR;
            return true;
        }    

        if (s_tsd_str_cmp(ems_subsrc, subsrc_tsd_size, DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_BRIDGE_CROSSCHAIN)==0)
        {   
            *a_action =  DAP_CHAIN_TX_TAG_ACTION_TRANSFER_CROSSCHAIN;
            return true;
        }
    }
    return false;
}


static bool s_tag_check_bridge(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,  dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{
    //bridged native transfer: destination addr netid differs from net we get datum
    //such tx are marked by TRANSFER service as CROSSCHAIN_TRANSFER
    //bridge txs are only received one
    

    //crosschain bridge AUTH emissions 
    
    if (!a_items_grp->items_in_ems)
        return false;

    dap_chain_tx_in_ems_t *l_tx_in_ems = a_items_grp->items_in_ems->data;
    dap_hash_fast_t ems_hash = l_tx_in_ems->header.token_emission_hash;
    dap_chain_datum_token_emission_t *l_emission = dap_ledger_token_emission_find(a_ledger, &ems_hash);
    if(l_emission)
        return s_get_ems_bridge_action(l_emission, a_action);

    return false;
}

int dap_chain_net_srv_bridge_init()
{
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_BRIDGE_ID };
    dap_ledger_service_add(l_uid, "bridge", s_tag_check_bridge);
    return 0;
}

void dap_chain_net_srv_bridge_deinit()
{
    
}

