#include <stdint.h>
#include "dap_strfuncs.h"
#include "rand/dap_rand.h"
#include "dap_chain_net_srv_common.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_utxo.h"

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
uint64_t dap_chain_net_srv_client_auth(char *a_addr_base58, uint8_t *a_sign, size_t a_sign_size,
        const dap_chain_net_srv_abstract_t **a_cond_out)
{
    dap_chain_addr_t *l_addr = (a_addr_base58) ? dap_chain_str_to_addr(a_addr_base58) : NULL;
    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    dap_chain_sign_type_t l_sig_type;
    if(l_addr)
        memcpy(&l_sig_type, &l_addr->sig_type, sizeof(dap_chain_sign_type_t));
    // Search all value in transactions with l_addr in 'out_cond' item
    uint64_t l_value = dap_chain_utxo_tx_cache_get_out_cond_value(l_addr, &l_tx_out_cond);
    DAP_DELETE(l_addr);
    // not found transaction with l_addr in 'out_cond' item
    if(!l_value)
        return 0;

    size_t l_pkey_size = 0;
    size_t l_cond_size = 0;
    uint8_t *l_cond = dap_chain_datum_tx_out_cond_item_get_cond(l_tx_out_cond, &l_cond_size);
    uint8_t *l_pkey = dap_chain_datum_tx_out_cond_item_get_pkey(l_tx_out_cond, &l_pkey_size);

    // create l_chain_sign for check a_sign
    dap_chain_sign_t *l_chain_sign = DAP_NEW_Z_SIZE(dap_chain_sign_t,
            sizeof(dap_chain_sign_t) + a_sign_size + l_pkey_size);
    l_chain_sign->header.type = l_sig_type;
    l_chain_sign->header.sign_size = l_pkey_size;
    l_chain_sign->header.sign_pkey_size = l_pkey_size;
    // write serialized public key to dap_chain_sign_t
    memcpy(l_chain_sign->pkey_n_sign, l_pkey, l_pkey_size);
    // write serialized signature to dap_chain_sign_t
    memcpy(l_chain_sign->pkey_n_sign + l_pkey_size, a_sign, a_sign_size);

    // check signature
    if(dap_chain_sign_verify(l_chain_sign, a_sign, a_sign_size) != 1) {
        // invalid signature
        return 0;
    }

    if(l_cond_size != sizeof(dap_chain_net_srv_abstract_t)) {
        return 0;
    }
    if(a_cond_out)
        *a_cond_out = (const dap_chain_net_srv_abstract_t*) l_cond;
    return l_value;
}
