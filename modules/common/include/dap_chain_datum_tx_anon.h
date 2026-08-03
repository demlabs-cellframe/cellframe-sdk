/*
 * dap_chain_datum_tx_anon.h — Anonymous transaction item types.
 *
 * Defines structures for STARK-based anonymous transactions:
 * - Anonymous input (with ring membership proof)
 * - Anonymous output (with Pedersen commitment)
 * - Key image (for double-spend prevention)
 * - STARK proof (ring membership ZKP)
 */

#pragma once

#include "dap_chain_common.h"
#include "chipmunk_stark.h"
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

/* Minimum ring size for anonymity.
 * A ring with < 16 members provides weak anonymity — the signer is one of
 * only a few candidates. 16 members gives anonymity set of 2^4, making
 * correlation attacks significantly harder.
 * (Monero uses ring_size=16 as its minimum since 2022.) */
#define DAP_CHAIN_TX_ANON_MIN_RING_SIZE  16

/* Phase 9F: Maximum ring size accepted by the ledger.
 *
 * The LRS primitive itself caps at CHIPMUNK_LRS_RING_MAX (64), but the
 * ledger enforces the same upper bound explicitly and BEFORE any crypto
 * work so an attacker cannot force O(ring_size × NTT) verification on a
 * huge fabricated ring. Rings above this size are rejected at the wire
 * gate, not deep inside chipmunk_lrs_verify.
 *
 * Kept in sync with CHIPMUNK_LRS_RING_MAX via the static assert below. */
#define DAP_CHAIN_TX_ANON_MAX_RING_SIZE  64

/* Phase 9F: Hard cap on the serialized size of an anonymous transaction.
 *
 * A single anon TX at max ring (64 × 1424-byte CLPK + 8.5KB LRS sig + 4
 * OUT_ANON at ~61KB range proof each) is already ~620KB. 1 MiB leaves
 * headroom for future multi-input expansion while bounding the worst-case
 * verification cost per TX. Larger TXes are rejected at the wire gate. */
#define DAP_CHAIN_TX_ANON_MAX_TX_SIZE    (1024u * 1024u)

/* Phase 9F: Maximum number of anonymous transactions accepted per block.
 *
 * Each anon TX runs STARK (44 FRI queries) + LRS (ring-size NTTs) + BDLOP
 * range proof verification. At max ring this is ~100ms of crypto per TX.
 * Capping at 16/block bounds the per-block verification budget to ~1.6s
 * while still allowing meaningful throughput. */
#define DAP_CHAIN_TX_ANON_MAX_PER_BLOCK  16

/* -------------------------------------------------------------------------
 * Anonymous Input (TX_ITEM_TYPE_IN_ANON = 0xb0)
 *
 * Replaces standard TX_ITEM_TYPE_IN for anonymous transactions.
 * Contains STARK ring membership proof instead of traditional signature.
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

    /* STARK ring membership proof (anonymity layer).
     * Proves indicator is one-hot binary via FRI polynomial identity.
     * Does NOT prove knowledge of lattice secret — that's LRS below. */
    chipmunk_stark_proof_t stark_proof;

    /* LRS signature (lattice binding layer).
     * Proves knowledge of short x with A_pk·x = P_j for some P_j in ring.
     * Module-level ring signature — binds indicator to actual lattice key.
     * Variable-length, stored in trailing data after ring keys. */
    uint32_t lrs_sig_size;

    /* Ring commit hash: SHA3-256 of serialized ring public keys.
     * Used for ring dedup — if a ring with the same hash is already
     * published in a previous TX, the ring keys can be omitted from
     * this TX (looked up from GlobalDB ring cache instead).
     *
     * If ring_commit_hash is all zeros → ring keys are inline (trailing data).
     * If ring_commit_hash is nonzero → ring keys are in GDB cache,
     *   NOT included in trailing data. Saves ring_size × 1424 bytes per TX. */
    dap_hash_sha3_256_t ring_commit_hash;

    /* Ring of public keys used for the proof */
    uint32_t ring_size;
    /* Public keys follow this struct as variable-length data (unless dedup'd) */
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

    /* Phase 6-full: Ephemeral public key for stealth addresses.
     *
     * When nonzero, recipient scans blockchain: computes
     *   shared = H(scan_pk || ephemeral_pk)
     *   derived_sk = spend_sk + H(shared)
     *   derived_pk = A · derived_sk
     * and checks if addr matches derived_pk.
     *
     * If all zeros → standard (non-stealth) output, addr is direct. */
    uint8_t ephemeral_pk[CHIPMUNK_LRS_POLY_QPACK_BYTES];  /* 1408 bytes */

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
 * STARK Proof (TX_ITEM_TYPE_ANON_PROOF = 0xb3)
 *
 * Standalone STARK proof item for ring membership verification.
 * ---------------------------------------------------------------------- */

typedef struct dap_chain_tx_anon_proof {
    dap_chain_tx_anon_hdr_t hdr;

    /* STARK proof data */
    chipmunk_stark_proof_t proof;

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
 * Extract STARK proofs from anonymous TX items.
 * @return 0 on success, negative on error.
 */
int dap_chain_datum_tx_get_stark_proofs(const uint8_t *a_tx_items, size_t a_items_size,
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
 * Phase 9E: Comprehensive, chain-bound signed message context.
 *
 * The STARK + LRS proofs sign a single message. For the proof system to be
 * unforgeable that message must commit to EVERY attacker-relevant field of
 * the transaction, plus the chain context that scopes the proof. Otherwise
 * a proof minted for one TX can be replayed against a different TX that
 * shares only the (addr, ki, rp) triple the legacy message covered.
 *
 * Canonical binding (SHA3-256 over domain-separated fields):
 *   H( "chipchain-anon-msg-v2"
 *      || chain_id(8) || net_id(8)
 *      || ts_created(8)
 *      || count_OUT_ANON(4) || H(all OUT_ANON commitments)
 *      || count_IN_ANON(4)  || H(all IN_ANON prev_hash||out_idx)
 *      || ring_commit_hash(32) || ring_size(4)
 *      || ephemeral_pk(1408)
 *      || token_ticker(DAP_CHAIN_TICKER_SIZE_MAX)
 *      || recipient_addr(sizeof(dap_chain_addr_t))
 *      || ki_hash(32) || rp_hash(32)
 *    )
 *
 * The verifier re-derives exactly the same byte sequence from the TX items
 * it actually validates, so a mismatch fails verification. Note:
 *   - ts_created is taken from the TX header so the proof is bound to the
 *     exact transaction it lives in (replay protection across time).
 *   - chain_id/net_id make the proof chain-specific (cross-chain replay
 *     protection).
 *   - ring_commit_hash binds the ring set; ring_size is included so a
 *     ring_commit_hash of all-zeros (inline mode) is still disambiguated
 *     by the inline ring length.
 *   - ephemeral_pk binds the stealth-address one-time key.
 */
typedef struct dap_chain_anon_msg_ctx {
    /* Chain context */
    uint64_t chain_id;          /* a_chain->id.uint64 */
    uint64_t net_id;            /* a_chain->net_id.uint64 */
    uint64_t ts_created;        /* tx->header.ts_created */

    /* Output set: hash of concatenated OUT_ANON commitments, in TX order. */
    dap_hash_sha3_256_t outputs_commit_hash;
    uint32_t out_anon_count;

    /* Input set: hash of concatenated (prev_hash || out_idx) for all IN_ANON,
     * in TX order. */
    dap_hash_sha3_256_t inputs_utxo_hash;
    uint32_t in_anon_count;

    /* Ring binding */
    dap_hash_sha3_256_t ring_commit_hash;   /* from IN_ANON (zero if inline) */
    uint32_t ring_size;

    /* Stealth address binding */
    const uint8_t *ephemeral_pk;            /* CHIPMUNK_LRS_POLY_QPACK_BYTES, or NULL */
    size_t ephemeral_pk_size;

    /* Legacy fields preserved for compatibility / human-readable binding */
    const dap_chain_addr_t *recipient_addr;
    const char *token_ticker;
    dap_hash_sha3_256_t ki_hash;
    dap_hash_sha3_256_t rp_hash;
} dap_chain_anon_msg_ctx_t;

/**
 * Phase 9E: Build the comprehensive, chain-bound signed message.
 *
 * Writes the canonical message bytes into a_out. Both compose side
 * (dap_chain_tx_anon_create) and verify side (dap_chain_ledger_type) MUST
 * populate the context identically from the TX they are signing/verifying.
 *
 * @return bytes written on success, negative errno on error.
 */
ssize_t dap_chain_anon_stark_build_message_v2(uint8_t *a_out, size_t a_out_size,
                                               const dap_chain_anon_msg_ctx_t *a_ctx);

/**
 * Phase 9E: Required output buffer size for build_message_v2.
 * Callers may use this to size dynamic buffers.
 */
size_t dap_chain_anon_stark_message_v2_size(void);

/**
 * Build STARK message binding: addr || commit_hash || ticker || ki_hash || rp_hash.
 *
 * Used by both compose side (chipmunk_stark_prove) and verify side
 * (chipmunk_stark_verify) to ensure the Fiat-Shamir transcript binds the
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
ssize_t dap_chain_anon_stark_build_message(uint8_t *a_out, size_t a_out_size,
                                           const dap_chain_addr_t *a_addr,
                                           const dap_hash_sha3_256_t *a_commit_hash,
                                           const char *a_ticker,
                                           const dap_hash_sha3_256_t *a_ki_hash,
                                           const dap_hash_sha3_256_t *a_rp_hash);

/**
 * Phase 9D: Bind a wallet-level key image to a specific UTXO.
 *
 * Given a raw signer-constant key image (the I poly = A_I·x produced by
 * chipmunk_lrs_key_image, q-packed), mix in the spent UTXO coordinates so
 * that each (signer, UTXO) pair commits a unique double-spend tag.
 *
 * The canonical binding is the first 32 bytes of:
 *   SHA3-256( raw_key_image[a_ki_size] || prev_hash[32] || prev_out_idx[4] )
 *
 * The output buffer receives the 32-byte hash in its first 32 bytes; any
 * bytes beyond that are zeroed (so callers can keep the full 9216-byte
 * TX key_image layout). Used by both compose side (dap_chain_tx_anon_create)
 * and verify side (dap_chain_ledger_type) to recompute the expected TX
 * key_image from the link-tag embedded in the LRS signature.
 *
 * @param a_ki_out       Output buffer (>= max(32, a_ki_size) bytes).
 * @param a_ki_size      Total size of a_ki_out (e.g. 9216 for the TX field).
 * @param a_raw_ki       Raw signer-constant key image bytes.
 * @param a_raw_ki_size  Number of bytes in a_raw_ki.
 * @param a_prev_hash    Previous TX hash (the UTXO being spent).
 * @param a_prev_out_idx Output index within the previous TX.
 */
void dap_chain_anon_bind_key_image_to_utxo(uint8_t *a_ki_out, size_t a_ki_size,
                                            const uint8_t *a_raw_ki, size_t a_raw_ki_size,
                                            const dap_chain_hash_fast_t *a_prev_hash,
                                            uint32_t a_prev_out_idx);

#ifdef __cplusplus
}
#endif
