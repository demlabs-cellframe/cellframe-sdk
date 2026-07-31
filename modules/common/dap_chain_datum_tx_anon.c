/*
 * dap_chain_datum_tx_anon.c — Anonymous transaction item helpers.
 *
 * GAP-21 FIX: All hand-rolled item iterators replaced with canonical
 * TX_ITEM_ITER macro (uses dap_chain_datum_item_tx_get_size which
 * correctly handles all item types, not just anon items).
 */

#include "dap_chain_datum_tx_anon.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_common.h"
#include "dap_hash_sha3.h"
#include "dap_memwipe.h"

#include <string.h>
#include <errno.h>

#define LOG_TAG "datum_tx_anon"

bool dap_chain_datum_tx_is_anonymous(const uint8_t *a_tx_items, size_t a_items_size)
{
    if (!a_tx_items || a_items_size == 0) return false;

    /* GAP-21 FIX: Use canonical TX_ITEM_ITER instead of hand-rolled parser.
     * The old parser assumed ALL items have uint32 size at offset 4 — only
     * true for anon items, not for IN/OUT_STD. This caused garbage size reads
     * and detection bypass. */
    const uint8_t *l_item;
    size_t l_item_size;
    TX_ITEM_ITER(l_item, l_item_size, a_tx_items, a_items_size) {
        uint8_t l_type = *l_item;
        if (l_type == TX_ITEM_TYPE_IN_ANON || l_type == TX_ITEM_TYPE_OUT_ANON ||
            l_type == TX_ITEM_TYPE_KEY_IMAGE || l_type == TX_ITEM_TYPE_ANON_PROOF ||
            l_type == TX_ITEM_TYPE_PEDERSEN_COMMIT) {
            return true;
        }
    }

    return false;
}

int dap_chain_datum_tx_get_key_images(const uint8_t *a_tx_items, size_t a_items_size,
                                       const dap_chain_tx_key_image_t ***a_images,
                                       size_t *a_count)
{
    if (!a_tx_items || !a_images || !a_count) return -EINVAL;

    /* GAP-21 FIX: Use canonical TX_ITEM_ITER for correct item traversal. */
    /* First pass: count KEY_IMAGE items */
    size_t l_count = 0;
    const uint8_t *l_item;
    size_t l_item_size;
    TX_ITEM_ITER(l_item, l_item_size, a_tx_items, a_items_size) {
        if (*l_item == TX_ITEM_TYPE_KEY_IMAGE) l_count++;
    }

    if (l_count == 0) { *a_images = NULL; *a_count = 0; return 0; }

    const dap_chain_tx_key_image_t **l_images = DAP_NEW_Z_COUNT(const dap_chain_tx_key_image_t *, l_count);
    if (!l_images) return -ENOMEM;

    /* Second pass: collect */
    size_t l_idx = 0;
    TX_ITEM_ITER(l_item, l_item_size, a_tx_items, a_items_size) {
        if (*l_item == TX_ITEM_TYPE_KEY_IMAGE && l_idx < l_count) {
            l_images[l_idx++] = (const dap_chain_tx_key_image_t *)l_item;
        }
    }

    *a_images = l_images;
    *a_count = l_count;
    return 0;
}

int dap_chain_datum_tx_get_stark_proofs(const uint8_t *a_tx_items, size_t a_items_size,
                                         const dap_chain_tx_anon_proof_t ***a_proofs,
                                         size_t *a_count)
{
    if (!a_tx_items || !a_proofs || !a_count) return -EINVAL;

    /* GAP-21 FIX: Use canonical TX_ITEM_ITER. */
    size_t l_count = 0;
    const uint8_t *l_item;
    size_t l_item_size;
    TX_ITEM_ITER(l_item, l_item_size, a_tx_items, a_items_size) {
        if (*l_item == TX_ITEM_TYPE_ANON_PROOF) l_count++;
    }

    if (l_count == 0) { *a_proofs = NULL; *a_count = 0; return 0; }

    const dap_chain_tx_anon_proof_t **l_proofs = DAP_NEW_Z_COUNT(const dap_chain_tx_anon_proof_t *, l_count);
    if (!l_proofs) return -ENOMEM;

    size_t l_idx = 0;
    TX_ITEM_ITER(l_item, l_item_size, a_tx_items, a_items_size) {
        if (*l_item == TX_ITEM_TYPE_ANON_PROOF && l_idx < l_count) {
            l_proofs[l_idx++] = (const dap_chain_tx_anon_proof_t *)l_item;
        }
    }

    *a_proofs = l_proofs;
    *a_count = l_count;
    return 0;
}

void dap_chain_anon_input_commit_seed(uint8_t a_seed[32],
                                       const dap_chain_hash_fast_t *a_prev_hash,
                                       uint32_t a_prev_out_idx)
{
    uint8_t l_buf[sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t) + 24];
    size_t l_off = 0;
    memcpy(l_buf + l_off, a_prev_hash, sizeof(dap_chain_hash_fast_t));
    l_off += sizeof(dap_chain_hash_fast_t);
    memcpy(l_buf + l_off, &a_prev_out_idx, sizeof(uint32_t));
    l_off += sizeof(uint32_t);
    memcpy(l_buf + l_off, "chipchain-anon-input-v1", 23);
    l_off += 23;
    dap_hash_sha3_256_raw(a_seed, l_buf, l_off);
}

ssize_t dap_chain_anon_stark_build_message(uint8_t *a_out, size_t a_out_size,
                                           const dap_chain_addr_t *a_addr,
                                           const dap_hash_sha3_256_t *a_commit_hash,
                                           const char *a_ticker,
                                           const dap_hash_sha3_256_t *a_ki_hash,
                                           const dap_hash_sha3_256_t *a_rp_hash)
{
    size_t l_needed = sizeof(dap_chain_addr_t) + 32 + DAP_CHAIN_TICKER_SIZE_MAX + 32 + 32;
    if (!a_out || a_out_size < l_needed)
        return -ENOMEM;
    if (!a_addr || !a_commit_hash || !a_ticker || !a_ki_hash || !a_rp_hash)
        return -EINVAL;

    size_t l_off = 0;
    memcpy(a_out + l_off, a_addr, sizeof(dap_chain_addr_t)); l_off += sizeof(dap_chain_addr_t);
    memcpy(a_out + l_off, a_commit_hash->raw, 32); l_off += 32;
    size_t l_tl = strnlen(a_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    memcpy(a_out + l_off, a_ticker, l_tl); l_off += l_tl;
    memcpy(a_out + l_off, a_ki_hash->raw, 32); l_off += 32;
    memcpy(a_out + l_off, a_rp_hash->raw, 32); l_off += 32;
    return (ssize_t)l_off;
}

void dap_chain_anon_bind_key_image_to_utxo(uint8_t *a_ki_out, size_t a_ki_size,
                                            const uint8_t *a_raw_ki, size_t a_raw_ki_size,
                                            const dap_chain_hash_fast_t *a_prev_hash,
                                            uint32_t a_prev_out_idx)
{
    if (!a_ki_out || !a_raw_ki || !a_prev_hash || a_ki_size < sizeof(dap_hash_sha3_256_t))
        return;

    /* Canonical binding:
     *   SHA3-256( raw_ki || prev_hash(32) || prev_out_idx(4) )
     * then keep first 32 bytes, zero the rest of a_ki_out.
     *
     * Build the preimage in a heap buffer because the raw I poly can be large
     * (CHIPMUNK_LRS_POLY_QPACK_BYTES = 1408) and the compose side historically
     * used a 9216-byte raw slot.
     */
    size_t l_buf_size = a_raw_ki_size + sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t);
    uint8_t *l_buf = DAP_NEW_Z_SIZE(uint8_t, l_buf_size);
    if (!l_buf) {
        /* OOM: zero the output so no stale secret leaks. */
        memset(a_ki_out, 0, a_ki_size);
        return;
    }
    size_t l_off = 0;
    memcpy(l_buf + l_off, a_raw_ki, a_raw_ki_size);
    l_off += a_raw_ki_size;
    memcpy(l_buf + l_off, a_prev_hash, sizeof(dap_chain_hash_fast_t));
    l_off += sizeof(dap_chain_hash_fast_t);
    memcpy(l_buf + l_off, &a_prev_out_idx, sizeof(uint32_t));
    l_off += sizeof(uint32_t);

    dap_hash_sha3_256_raw(a_ki_out, l_buf, l_off);
    if (a_ki_size > sizeof(dap_hash_sha3_256_t))
        memset(a_ki_out + sizeof(dap_hash_sha3_256_t), 0,
               a_ki_size - sizeof(dap_hash_sha3_256_t));

    dap_memwipe(l_buf, l_buf_size);
    DAP_DELETE(l_buf);
}
