/*
 * dap_chain_datum_tx_anon.h — Anonymous transaction item types.
 *
 * Defines structures for SNARK-based anonymous transactions:
 * - Anonymous input (with ring membership proof)
 * - Anonymous output (with Pedersen commitment)
 * - Key image (for double-spend prevention)
 * - SNARK proof (ring membership ZKP)
 */

#pragma once

#include "dap_chain_common.h"
#include "chipmunk_snark.h"
#include "chipmunk_pedersen.h"
#include "chipmunk_range_proof.h"
#include "chipmunk_range_proof_bdlop.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Anonymous TX item header
 * ---------------------------------------------------------------------- */

/* Common header for all anonymous TX items */
typedef struct dap_chain_tx_anon_hdr {
    uint8_t type;                   /* TX_ITEM_TYPE_IN_ANON, etc. */
    uint8_t version;                /* Structure version */
    uint16_t padding;
    uint32_t size;                  /* Total item size */
} DAP_ALIGN_PACKED dap_chain_tx_anon_hdr_t;

/* -------------------------------------------------------------------------
 * Anonymous Input (TX_ITEM_TYPE_IN_ANON = 0xb0)
 *
 * Replaces standard TX_ITEM_TYPE_IN for anonymous transactions.
 * Contains LRS (Linkable Ring Signature) for ring membership proof.
 *
 * Phase 3 (P0-2 fix): The broken SNARK proof (z≡0 forge) was replaced
 * with chipmunk_lrs_sign/verify, which provides cryptographically
 * correct ring membership proof based on Module-SIS.
 * ---------------------------------------------------------------------- */

typedef struct dap_chain_tx_in_anon {
    dap_chain_tx_anon_hdr_t hdr;

    /* Previous TX hash (the UTXO being spent) */
    dap_chain_hash_fast_t prev_hash;

    /* Previous TX output index */
    uint32_t prev_out_idx;

    /* Key image for double-spend prevention
     * Key image = A_I * s (deterministic for each secret key)
     * Same key always produces same image → detect double-spend
     * without revealing which key was used */
    uint8_t key_image[9216];        /* k=6 q-packed polynomials */

    /* LRS ring membership proof (variable-length, follows after ring_size).
     * Proves: "I know sk_j for pk_j in {pk_0, ..., pk_{N-1}}" without revealing j.
     * Replaces the broken SNARK proof (P0-2: z≡0 forge). */
    uint32_t lrs_sig_size;          /* Size of LRS signature in bytes */

    /* Ring of public keys used for the proof */
    uint32_t ring_size;
    /* Variable-length trailing data follows this struct:
     *   [lrs_sig_data: lrs_sig_size bytes]
     *   [ring_keys: ring_size * sizeof(chipmunk_lrs_public_key_t) bytes]
     */
} DAP_ALIGN_PACKED dap_chain_tx_in_anon_t;

/* -------------------------------------------------------------------------
 * Anonymous Output (TX_ITEM_TYPE_OUT_ANON = 0xb1)
 *
 * Contains Pedersen commitment to amount instead of plaintext value.
 * ---------------------------------------------------------------------- */

typedef struct dap_chain_tx_out_anon {
    dap_chain_tx_anon_hdr_t hdr;

    /* Recipient address (can be stealth address for unlinkability) */
    dap_chain_addr_t addr;

    /* Pedersen commitment to amount: C = A*r + encode(amount)
     * Amount is hidden, only the commitment is published */
    chipmunk_pedersen_commit_t commitment;

    /* Range proof (BDLOP-based, Phase 2): proves amount ∈ [0, 2^64)
     * without revealing it. Uses lattice-based BDLOP commitment +
     * ABDLOP opening proof with rejection sampling.
     *
     * Proof size: ~385 KB (13 rounds × 14 polynomials).
     * Will be reduced to ~28 KB in Phase 2.6b (Gaussian masking).
     *
     * Legacy chipmunk_range_proof_t (Stern-like) was BROKEN (P0-1: z≡0 forge).
     * For backward compatibility, old-format proofs are stored as a
     * variable-length field after this struct (see hdr.size). */
    chipmunk_range_proof_bdlop_t range_proof;

    /* Token ticker (still visible for routing) */
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
} DAP_ALIGN_PACKED dap_chain_tx_out_anon_t;

/* -------------------------------------------------------------------------
 * Key Image (TX_ITEM_TYPE_KEY_IMAGE = 0xb2)
 *
 * Standalone key image item for double-spend prevention.
 * Can be included in TX or stored separately in ledger.
 * ---------------------------------------------------------------------- */

typedef struct dap_chain_tx_key_image {
    dap_chain_tx_anon_hdr_t hdr;

    /* Key image: I = A_I * s (deterministic for each secret key) */
    uint8_t image[9216];            /* k=6 q-packed polynomials */

    /* Hash of the image for quick lookup */
    dap_chain_hash_fast_t image_hash;
} DAP_ALIGN_PACKED dap_chain_tx_key_image_t;

/* -------------------------------------------------------------------------
 * SNARK Proof (TX_ITEM_TYPE_ANON_PROOF = 0xb3)
 *
 * Standalone SNARK proof item for ring membership verification.
 * ---------------------------------------------------------------------- */

typedef struct dap_chain_tx_anon_proof {
    dap_chain_tx_anon_hdr_t hdr;

    /* SNARK proof data */
    chipmunk_snark_proof_t proof;

    /* Ring hash (for verifier to look up ring) */
    dap_chain_hash_fast_t ring_hash;

    /* Message hash (what was signed) */
    dap_chain_hash_fast_t msg_hash;
} DAP_ALIGN_PACKED dap_chain_tx_anon_proof_t;

/* -------------------------------------------------------------------------
 * Pedersen Commitment (TX_ITEM_TYPE_PEDERSEN_COMMIT = 0xb4)
 *
 * Standalone commitment item for confidential amounts.
 * ---------------------------------------------------------------------- */

typedef struct dap_chain_tx_pedersen_commit {
    dap_chain_tx_anon_hdr_t hdr;

    /* Pedersen commitment */
    chipmunk_pedersen_commit_t commit;

    /* Range proof (optional, for verification) */
    bool has_range_proof;
    chipmunk_range_proof_t range_proof;
} DAP_ALIGN_PACKED dap_chain_tx_pedersen_commit_t;

/* -------------------------------------------------------------------------
 * Helper functions
 * ---------------------------------------------------------------------- */

/**
 * Get anonymous input from TX item pointer.
 * @return Pointer to dap_chain_tx_in_anon_t or NULL if wrong type.
 */
static inline dap_chain_tx_in_anon_t *dap_chain_tx_item_get_in_anon(const uint8_t *a_item)
{
    if (!a_item || *a_item != TX_ITEM_TYPE_IN_ANON) return NULL;
    return (dap_chain_tx_in_anon_t *)a_item;
}

/**
 * Get anonymous output from TX item pointer.
 */
static inline dap_chain_tx_out_anon_t *dap_chain_tx_item_get_out_anon(const uint8_t *a_item)
{
    if (!a_item || *a_item != TX_ITEM_TYPE_OUT_ANON) return NULL;
    return (dap_chain_tx_out_anon_t *)a_item;
}

/**
 * Get key image from TX item pointer.
 */
static inline dap_chain_tx_key_image_t *dap_chain_tx_item_get_key_image(const uint8_t *a_item)
{
    if (!a_item || *a_item != TX_ITEM_TYPE_KEY_IMAGE) return NULL;
    return (dap_chain_tx_key_image_t *)a_item;
}

/**
 * Check if TX items contain anonymous items.
 * @param a_tx_items Raw TX items byte array.
 * @param a_items_size Size of items array.
 * @return true if TX has any anonymous items.
 */
bool dap_chain_datum_tx_is_anonymous(const uint8_t *a_tx_items, size_t a_items_size);

/**
 * Extract key images from anonymous TX items.
 * @param a_tx_items Raw TX items byte array.
 * @param a_items_size Size of items array.
 * @param a_images Output array of key image pointers (caller frees array, not images).
 * @param a_count Output count of key images.
 * @return 0 on success, negative on error.
 */
int dap_chain_datum_tx_get_key_images(const uint8_t *a_tx_items, size_t a_items_size,
                                       const dap_chain_tx_key_image_t ***a_images,
                                       size_t *a_count);

/**
 * Extract SNARK proofs from anonymous TX items.
 * @return 0 on success, negative on error.
 */
int dap_chain_datum_tx_get_snark_proofs(const uint8_t *a_tx_items, size_t a_items_size,
                                         const dap_chain_tx_anon_proof_t ***a_proofs,
                                         size_t *a_count);

/**
 * Compute deterministic input blinding seed for Pedersen conservation.
 *
 * Used by both compose side (to derive anchor output blinding) and
 * verify side (to reconstruct input Pedersen commitment).
 *
 * seed = SHA256(prev_hash || prev_out_idx || "chipchain-anon-input-v1")
 */
void dap_chain_anon_input_commit_seed(uint8_t a_seed[32],
                                       const dap_chain_hash_fast_t *a_prev_hash,
                                       uint32_t a_prev_out_idx);

/**
 * Build SNARK message binding: addr || commit_hash || ticker || ki_hash || rp_hash.
 *
 * Used by both compose side (chipmunk_snark_prove) and verify side
 * (chipmunk_snark_verify) to ensure the Fiat-Shamir transcript binds the
 * proof to the same statement.  The message layout MUST match on both
 * sides or proof verification will fail.
 *
 * @param a_out          Output buffer (at least sizeof(dap_chain_addr_t) + 32*3 + DAP_CHAIN_TICKER_SIZE_MAX).
 * @param a_out_size     Size of output buffer.
 * @param a_addr         Recipient address.
 * @param a_commit_hash SHA-256 of the Pedersen commitment.
 * @param a_ticker       Token ticker string (NUL-terminated).
 * @param a_ki_hash      SHA-256 of the key image.
 * @param a_rp_hash      SHA-256 of the range proof.
 * @return              Number of bytes written, or negative on error.
 */
ssize_t dap_chain_anon_snark_build_message(uint8_t *a_out, size_t a_out_size,
                                           const dap_chain_addr_t *a_addr,
                                           const dap_hash_sha3_256_t *a_commit_hash,
                                           const char *a_ticker,
                                           const dap_hash_sha3_256_t *a_ki_hash,
                                           const dap_hash_sha3_256_t *a_rp_hash);

#ifdef __cplusplus
}
#endif
