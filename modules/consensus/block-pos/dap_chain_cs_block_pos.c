/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2021
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

#include "dap_chain_net.h"
#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_cs_block_pos.h"
#include "dap_chain_net_srv_stake.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "dap_chain_cs_block_pos"

typedef struct dap_chain_cs_block_pos_pvt
{
    dap_enc_key_t *blocks_sign_key;
    char **tokens_hold;
    uint64_t *tokens_hold_value;
    size_t tokens_hold_size;
    uint16_t confirmations_minimum;
    dap_chain_callback_new_cfg_t prev_callback_created;
} dap_chain_cs_block_pos_pvt_t;

#define PVT(a) ((dap_chain_cs_block_pos_pvt_t *)a->_pvt)

static void s_callback_delete(dap_chain_cs_blocks_t *a_blocks);
static int s_callback_new(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
static int s_callback_created(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
static int s_callback_block_verify(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size);
static size_t s_callback_block_sign(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t **a_block_ptr, size_t a_block_size);

/**
 * @brief dap_chain_cs_block_pos_init
 * @return
 */
int dap_chain_cs_block_pos_init()
{
    dap_chain_cs_add("block_pos", s_callback_new);
    return 0;
}

/**
 * @brief dap_chain_cs_block_pos_deinit
 */
void dap_chain_cs_block_pos_deinit(void)
{

}

/**
 * @brief s_cs_callback
 * @param a_chain
 * @param a_chain_cfg
 */
static int s_callback_new(dap_chain_t *a_chain, dap_config_t *a_chain_cfg)
{
    dap_chain_cs_blocks_new(a_chain, a_chain_cfg);
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_cs_block_pos_t *l_pos = DAP_NEW_Z(dap_chain_cs_block_pos_t);
    l_blocks->_inheritor = l_pos;
    l_blocks->callback_delete = s_callback_delete;
    l_blocks->callback_block_verify = s_callback_block_verify;
    l_blocks->callback_block_sign = s_callback_block_sign;
    l_pos->_pvt = DAP_NEW_Z(dap_chain_cs_block_pos_pvt_t);

    dap_chain_cs_block_pos_pvt_t *l_pos_pvt = PVT(l_pos);

    char ** l_tokens_hold = NULL;
    char ** l_tokens_hold_value_str = NULL;
    uint16_t l_tokens_hold_size = 0;
    uint16_t l_tokens_hold_value_size = 0;

    l_tokens_hold = dap_config_get_array_str(a_chain_cfg, "block-pos", "stake_tokens", &l_tokens_hold_size);
    l_tokens_hold_value_str = dap_config_get_array_str(a_chain_cfg, "block-pos", "stake_tokens_value", &l_tokens_hold_value_size);

    if (l_tokens_hold_size != l_tokens_hold_value_size){
        log_it(L_CRITICAL, "Entries tokens_hold and tokens_hold_value are different size!");
        goto lb_err;
    }
    l_pos_pvt->confirmations_minimum = dap_config_get_item_uint16_default(a_chain_cfg, "block-pos", "verifications_minimum", 1);
    l_pos_pvt->tokens_hold_size = l_tokens_hold_size;
    l_pos_pvt->tokens_hold = DAP_NEW_Z_SIZE(char *, sizeof(char *) * l_tokens_hold_size);
    l_pos_pvt->tokens_hold_value = DAP_NEW_Z_SIZE(uint64_t, l_tokens_hold_value_size * sizeof(uint64_t));

    for (size_t i = 0; i < l_tokens_hold_value_size; i++) {
        l_pos_pvt->tokens_hold[i] = dap_strdup(l_tokens_hold[i]);
        if ((l_pos_pvt->tokens_hold_value[i] =
               strtoull(l_tokens_hold_value_str[i],NULL,10)) == 0) {
             log_it(L_CRITICAL, "Token %s has inproper hold value %s",
                                l_pos_pvt->tokens_hold[i], l_tokens_hold_value_str[i]);
             goto lb_err;
        }
    }
    // Save old callback if present and set the call of its own (chain callbacks)
    l_pos_pvt->prev_callback_created = l_blocks->chain->callback_created;
    l_blocks->chain->callback_created = s_callback_created;
    return 0;

lb_err:
    for (int i = 0; i < l_tokens_hold_size; i++)
        DAP_DELETE(l_tokens_hold[i]);
    DAP_DELETE(l_tokens_hold);
    DAP_DELETE(l_pos_pvt->tokens_hold_value);
    DAP_DELETE(l_pos_pvt);
    DAP_DELETE(l_pos );
    l_blocks->_inheritor = NULL;
    l_blocks->callback_delete = NULL;
    l_blocks->callback_block_verify = NULL;
    return -1;

}

/**
 * @brief s_callback_created
 * @param a_chain
 * @param a_chain_cfg
 * @return
 */
static int s_callback_created(dap_chain_t *a_chain, dap_config_t *a_chain_net_cfg)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_cs_block_pos_t *l_pos = DAP_CHAIN_CS_BLOCK_POS(l_blocks);

    const char * l_sign_cert_str = NULL;
    if ((l_sign_cert_str = dap_config_get_item_str(a_chain_net_cfg,"block-pos","blocks-sign-cert")) != NULL) {
        dap_cert_t *l_sign_cert = dap_cert_find_by_name(l_sign_cert_str);
        if (l_sign_cert == NULL) {
            log_it(L_ERROR, "Can't load sign certificate, name \"%s\" is wrong", l_sign_cert_str);
        } else if (l_sign_cert->enc_key->priv_key_data) {
            PVT(l_pos)->blocks_sign_key = l_sign_cert->enc_key;
            log_it(L_NOTICE, "Loaded \"%s\" certificate to sign PoS blocks", l_sign_cert_str);
        } else {
            log_it(L_ERROR, "Certificate \"%s\" has no private key", l_sign_cert_str);
        }
    } else {
        log_it(L_ERROR, "No sign certificate provided, can't sign any blocks");
    }
    return 0;
}


/**
 * @brief s_chain_cs_block_callback_delete
 * @param a_block
 */
static void s_callback_delete(dap_chain_cs_blocks_t *a_blocks)
{
    dap_chain_cs_block_pos_t *l_pos = DAP_CHAIN_CS_BLOCK_POS(a_blocks);
    if (l_pos->_pvt)
        DAP_DELETE(l_pos->_pvt);
}

/**
 * @brief
 * function makes block singing
 * @param a_block a_blocks dap_chain_cs_blocks_t
 * @param a_block dap_chain_block_t
 * @param a_block_size size_t size of block object
 * @return int
 */
static size_t s_callback_block_sign(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t **a_block_ptr, size_t a_block_size)
{
    assert(a_blocks);
    dap_chain_cs_block_pos_t *l_pos = DAP_CHAIN_CS_BLOCK_POS(a_blocks);
    dap_chain_cs_block_pos_pvt_t *l_pos_pvt = PVT(l_pos);
    if (!l_pos_pvt->blocks_sign_key) {
        log_it(L_WARNING, "Can't sign block with blocks-sign-cert in [block-pos] section");
        return 0;
    }
    if (!a_block_ptr || !(*a_block_ptr) || !a_block_size) {
        log_it(L_WARNING, "Block size or block pointer is NULL");
        return 0;
    }
    return dap_chain_block_sign_add(a_block_ptr, a_block_size, l_pos_pvt->blocks_sign_key);
}

/**
 * @brief 
 * function makes block singing verification
 * @param a_block a_blocks dap_chain_cs_blocks_t
 * @param a_block dap_chain_block_t
 * @param a_block_size size_t size of block object
 * @return int 
 */
static int s_callback_block_verify(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size)
{
    dap_chain_cs_block_pos_t *l_pos = DAP_CHAIN_CS_BLOCK_POS(a_blocks);
    dap_chain_cs_block_pos_pvt_t *l_pos_pvt = PVT(l_pos);

    if (a_blocks->chain->ledger == NULL) {
        log_it(L_CRITICAL,"Ledger is NULL can't check PoS on this chain %s", a_blocks->chain->name);
        return -3;
    }

    if (sizeof(a_block->hdr) >= a_block_size) {
        log_it(L_WARNING,"Incorrect size with block %p on chain %s", a_block, a_blocks->chain->name);
        return  -7;
    }

    size_t l_signs_count = dap_chain_block_get_signs_count(a_block, a_block_size);
    if (l_signs_count < l_pos_pvt->confirmations_minimum) {
        log_it(L_WARNING,"Wrong signature number with block %p on chain %s", a_block, a_blocks->chain->name);
        return -2; // Wrong signatures number
    }

    uint16_t l_verified_num = 0;
    for (size_t l_sig_pos = 0; l_sig_pos < l_signs_count; l_sig_pos++) {
        dap_sign_t *l_sign = dap_chain_block_sign_get(a_block, a_block_size, l_sig_pos);
        if (l_sign == NULL) {
            log_it(L_WARNING, "Block isn't signed with anything: sig pos %zu, event size %zu", l_sig_pos, a_block_size);
            return -4;
        }

        bool l_sign_size_correct = dap_sign_verify_size(l_sign, a_block_size);
        if (!l_sign_size_correct) {
            log_it(L_WARNING, "Block's sign #%zu size is incorrect", l_sig_pos);
            return -44;
        }
        size_t l_block_data_size = dap_chain_block_get_sign_offset(a_block, a_block_size);
        if (l_block_data_size == a_block_size) {
            log_it(L_WARNING,"Block has nothing except sign, nothing to verify so I pass it (who knows why we have it?)");
            return 0;
        }

        int l_sign_verified = dap_sign_verify(l_sign, a_block, l_block_data_size);
        if (l_sign_verified != 1) {
            log_it(L_WARNING, "Block's sign is incorrect: code %d", l_sign_verified);
            return -41;
        }

        if (l_sig_pos == 0) {
            dap_chain_addr_t l_addr = {};
            dap_chain_hash_fast_t l_pkey_hash;
            dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
            dap_chain_addr_fill(&l_addr, l_sign->header.type, &l_pkey_hash, a_blocks->chain->net_id);
            size_t l_datums_count = 0;
            dap_chain_datum_t **l_datums = dap_chain_block_get_datums(a_block, a_block_size, &l_datums_count);
            if (!l_datums || !l_datums_count) {
                log_it(L_WARNING, "No datums in block %p on chain %s", a_block, a_blocks->chain->name);
                return -7;
            }
            for (size_t i = 0; i < l_datums_count; i++) {
                if (!dap_chain_net_srv_stake_validator(&l_addr, l_datums[i])) {
                    log_it(L_WARNING, "Not passed stake validator datum %zu with block %p on chain %s", i, a_block, a_blocks->chain->name);
                    DAP_DELETE(l_datums);
                    return -6;
                }
            }
            DAP_DELETE(l_datums);
        }
    }

    // Check number
    if (l_verified_num >= l_pos_pvt->confirmations_minimum) {
        // Passed all checks
        return 0;
    } else {
        log_it(L_WARNING, "Wrong block: only %hu/%hu signs are valid", l_verified_num, l_pos_pvt->confirmations_minimum);
        return -2;
    }
}
