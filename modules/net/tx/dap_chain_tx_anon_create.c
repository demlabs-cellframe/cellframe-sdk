/*
 * dap_chain_tx_anon_create.c — Anonymous transaction creation implementation.
 *
 * Creates transactions with SNARK ring proofs, key images, and Pedersen commitments.
 * All stubs resolved: wallet key extraction, key image generation, UTXO lookup,
 * signer index, auto-ring selection, balance reveal.
 */

#include "dap_chain_tx_anon_create.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_anon.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_internal.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_type.h"
#include "dap_chain_ledger_anon_ctx.h"
#include "dap_chain_ledger_pvt.h"
#include "dap_chain_net.h"
#include "dap_chain_net_core.h"
#include "dap_chain_wallet_cache.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_net_srv_stake_common.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "chipmunk_snark.h"
#include "chipmunk_pedersen.h"
#include "chipmunk_range_proof.h"
#include "chipmunk_ring.h"
#include "chipmunk_lrs.h"
#include "chipmunk_mring.h"
#include "lotrs_sample.h"
#include "dap_enc_key.h"
#include "dap_pkey.h"
#include "dap_sign.h"
#include "dap_hash.h"
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_math_convert.h"
#include "dap_config.h"
#include "dap_rand.h"
#include "dap_memwipe.h"

#include <string.h>
#include <errno.h>
#include <stdint.h>

#define LOG_TAG "tx_anon_create"

/* Crypto parameters (SNARK ctx, Pedersen params) are per-ledger,
 * stored in PVT(ledger)->anon_data as dap_ledger_anon_ctx_t.
 * No global context — each network has its own parameters. */

/* Algorithm adapter: abstracts over different ring signature types */
typedef struct dap_chain_tx_anon_algo {
    const char *name;                           /* "chipmunk_ring", "lrs", "mrng" */
    dap_enc_key_type_t key_type;                /* Expected enc_key type */

    /* Extract public key from enc_key (returns pointer into key, no copy) */
    const void *(*get_pk)(dap_enc_key_t *key);
    /* Extract secret key from enc_key */
    const void *(*get_sk)(dap_enc_key_t *key);
    /* Get public key size in bytes */
    size_t (*pk_size)(void);
    /* Compare two public keys (CT-safe) */
    int (*pk_cmp)(const void *a, const void *b);
    /* Generate key image from sk + pk */
    int (*key_image)(uint8_t out[9216], const void *pk, const void *sk, const lotrs_params_t *par);
    /* Extract pk from stake pkey raw data */
    int (*pk_from_stake_pkey)(void *out_pk, const dap_pkey_t *pkey);
    /* Populate SNARK witness secret_key polynomials from enc_key */
    int (*populate_witness)(chipmunk_snark_witness_t *witness, dap_enc_key_t *key);
} dap_chain_tx_anon_algo_t;

/* --- Chipmunk Ring adapter --- */
static const void *s_ring_get_pk(dap_enc_key_t *k) { return k->pub_key_data; }
static const void *s_ring_get_sk(dap_enc_key_t *k) { return k->priv_key_data; }
static size_t s_ring_pk_size(void) { return sizeof(chipmunk_ring_pk_t); }
static int s_ring_pk_cmp(const void *a, const void *b) {
    const chipmunk_ring_pk_t *la = (const chipmunk_ring_pk_t *)a;
    const chipmunk_ring_pk_t *lb = (const chipmunk_ring_pk_t *)b;
    for (uint32_t i = 0; i < la->a_hat.n && i < lb->a_hat.n; ++i) {
        if (!la->a_hat.polys[i] || !lb->a_hat.polys[i]) continue;
        for (uint32_t j = 0; j < 512; ++j) {
            int32_t d = la->a_hat.polys[i]->coeffs[j] - lb->a_hat.polys[i]->coeffs[j];
            if (d != 0) return (d > 0) ? 1 : -1;
        }
    }
    return 0;
}
static int s_ring_key_image(uint8_t out[9216], const void *pk, const void *sk, const lotrs_params_t *par) {
    /* Same as chipmunk_ring.c s_generate_key_image */
    const chipmunk_ring_pk_t *l_pk = (const chipmunk_ring_pk_t *)pk;
    const chipmunk_ring_sk_t *l_sk = (const chipmunk_ring_sk_t *)sk;
    lotrs_polymat_t l_A = lotrs_polymat_alloc(par, par->k, par->l);
    if (!l_A.rows) return -ENOMEM;
    const char *dom = "crin-key-image-v1";
    lotrs_xof_t *xof = lotrs_xof_new((const uint8_t *)dom, strlen(dom));
    if (!xof) { lotrs_polymat_free(&l_A); return -ENOMEM; }
    for (uint32_t i = 0; i < par->k; ++i) {
        uint8_t buf[2048];
        lotrs_poly_pack(buf, sizeof(buf), l_pk->a_hat.polys[i], par);
        lotrs_xof_absorb(xof, buf, lotrs_poly_bytes(par));
    }
    for (uint32_t i = 0; i < par->k; ++i)
        for (uint32_t j = 0; j < par->l; ++j)
            lotrs_sample_uniform(l_A.rows[i].polys[j], xof, par);
    lotrs_xof_free(xof);
    lotrs_polyvec_t I = lotrs_polyvec_alloc(par, par->k);
    if (!I.polys) { lotrs_polymat_free(&l_A); return -ENOMEM; }
    lotrs_polyvec_t ss = { .polys = l_sk->s.polys, .n = par->l };
    lotrs_polyvec_t st = { .polys = l_sk->s.polys + par->l, .n = par->k };
    lotrs_polymat_vecmul(&I, &l_A, &ss, par);
    lotrs_polyvec_add(&I, &I, &st, par);
    for (uint32_t i = 0; i < par->k; ++i)
        for (uint32_t j = 0; j < par->d; ++j)
            I.polys[i]->coeffs[j] = (uint64_t)lotrs_mod_reduce((__int128_t)(int64_t)I.polys[i]->coeffs[j], par->q);
    size_t l_poly_bytes = lotrs_poly_bytes(par);
    for (uint32_t i = 0; i < par->k; ++i)
        lotrs_poly_pack(out + i * l_poly_bytes, l_poly_bytes, I.polys[i], par);
    lotrs_polymat_free(&l_A);
    lotrs_polyvec_free(&I);
    return 0;
}
static int s_ring_pk_from_stake(void *out, const dap_pkey_t *pkey) {
    if (!out || !pkey) return -EINVAL;
    /* Check key type is Chipmunk (covers Ring, LRS, etc.) */
    if (pkey->header.type.raw != DAP_PKEY_TYPE_SIG_CHIPMUNK) return -EINVAL;
    if (pkey->header.size < sizeof(chipmunk_ring_pk_t)) return -EINVAL;
    memcpy(out, pkey->pkey, sizeof(chipmunk_ring_pk_t));
    return 0;
}
static int s_ring_populate_witness(chipmunk_snark_witness_t *witness, dap_enc_key_t *key) {
    const chipmunk_ring_sk_t *l_sk = (const chipmunk_ring_sk_t *)key->priv_key_data;
    if (!l_sk || !l_sk->s.polys) return -EINVAL;
    /* Copy l+k polynomials from the ring secret key polyvec into witness secret_key array.
     * l_sk->s.n should be (l+k), witness has CHIPMUNK_LRS_K*2 slots (l+k). */
    uint32_t l_n = l_sk->s.n;
    uint32_t l_max = CHIPMUNK_LRS_K * 2;
    if (l_n > l_max) l_n = l_max;
    for (uint32_t i = 0; i < l_n && i < l_max; ++i) {
        if (l_sk->s.polys[i]) {
            memcpy(&witness->secret_key[i], l_sk->s.polys[i], sizeof(chipmunk_poly_t));
        }
    }
    return 0;
}

static const dap_chain_tx_anon_algo_t s_algo_chipmunk_ring = {
    .name = "chipmunk_ring",
    .key_type = DAP_ENC_KEY_TYPE_SIG_CHIPMUNK_RING,
    .get_pk = s_ring_get_pk,
    .get_sk = s_ring_get_sk,
    .pk_size = s_ring_pk_size,
    .pk_cmp = s_ring_pk_cmp,
    .key_image = s_ring_key_image,
    .pk_from_stake_pkey = s_ring_pk_from_stake,
    .populate_witness = s_ring_populate_witness,
};

/* --- LRS adapter --- */
static const void *s_lrs_get_pk(dap_enc_key_t *k) { return k->pub_key_data; }
static const void *s_lrs_get_sk(dap_enc_key_t *k) { return k->priv_key_data; }
static size_t s_lrs_pk_size(void) { return sizeof(chipmunk_lrs_public_key_t); }
static int s_lrs_pk_cmp(const void *a, const void *b) {
    return memcmp(a, b, sizeof(chipmunk_lrs_public_key_t));
}
static int s_lrs_key_image(uint8_t out[9216], const void *pk, const void *sk, const lotrs_params_t *par) {
    (void)pk; (void)par;
    return chipmunk_lrs_key_image(out, (const chipmunk_lrs_secret_key_t *)sk);
}
static int s_lrs_pk_from_stake(void *out, const dap_pkey_t *pkey) {
    if (!out || !pkey) return -EINVAL;
    /* Check key type is Chipmunk (covers Ring, LRS, etc.) */
    if (pkey->header.type.raw != DAP_PKEY_TYPE_SIG_CHIPMUNK) return -EINVAL;
    if (pkey->header.size < sizeof(chipmunk_lrs_public_key_t)) return -EINVAL;
    memcpy(out, pkey->pkey, sizeof(chipmunk_lrs_public_key_t));
    return 0;
}
static int s_lrs_populate_witness(chipmunk_snark_witness_t *witness, dap_enc_key_t *key) {
    /* LRS secret key is seed-based; derive witness polynomials from x_seed.
     * witness->secret_key[K*2] = {s0[0..K-1], s1[0..K-1]}.
     * For LRS, s0 = x (derived witness), s1 = 0 (LRS is one-sided). */
    const chipmunk_lrs_secret_key_t *l_sk = (const chipmunk_lrs_secret_key_t *)key->priv_key_data;
    if (!l_sk) return -EINVAL;
    chipmunk_poly_t l_x[CHIPMUNK_LRS_K];
    int rc = chipmunk_lrs_derive_witness(l_x, l_sk->x_seed);
    if (rc != 0) return rc;
    /* Fill first K polynomials (s0 = x witness) */
    for (uint32_t i = 0; i < CHIPMUNK_LRS_K; ++i) {
        witness->secret_key[i] = l_x[i];
    }
    /* Second K polynomials (s1) remain zero — LRS doesn't use them */
    return 0;
}

static const dap_chain_tx_anon_algo_t s_algo_lrs = {
    .name = "lrs",
    .key_type = DAP_ENC_KEY_TYPE_SIG_CHIPMUNK_LRS,
    .get_pk = s_lrs_get_pk,
    .get_sk = s_lrs_get_sk,
    .pk_size = s_lrs_pk_size,
    .pk_cmp = s_lrs_pk_cmp,
    .key_image = s_lrs_key_image,
    .pk_from_stake_pkey = s_lrs_pk_from_stake,
    .populate_witness = s_lrs_populate_witness,
};

/* --- Algorithm registry --- */
static const dap_chain_tx_anon_algo_t *s_algos[] = {
    &s_algo_chipmunk_ring,
    &s_algo_lrs,
};
static const size_t s_algo_count = sizeof(s_algos) / sizeof(s_algos[0]);

static const dap_chain_tx_anon_algo_t *s_algo_find(const char *name) {
    for (size_t i = 0; i < s_algo_count; ++i) {
        if (strcmp(s_algos[i]->name, name) == 0) return s_algos[i];
    }
    return NULL;
}

/* --- Helpers using algorithm adapter --- */

static int s_find_signer_in_ring(const dap_chain_tx_anon_algo_t *algo,
                                  const void *a_ring, size_t a_ring_size,
                                  const void *a_signer_pk, uint32_t *a_index_out)
{
    size_t pk_sz = algo->pk_size();
    uint32_t l_idx = UINT32_MAX;
    for (size_t i = 0; i < a_ring_size; ++i) {
        if (algo->pk_cmp((const uint8_t *)a_ring + i * pk_sz, a_signer_pk) == 0) {
            l_idx = (uint32_t)i;
        }
    }
    if (l_idx == UINT32_MAX) return -ENOENT;
    *a_index_out = l_idx;
    return 0;
}

/* Forward declaration */
static void s_bind_key_image_to_utxo(uint8_t *a_ki, size_t a_ki_size,
                                     const dap_chain_hash_fast_t *a_prev_hash,
                                     uint32_t a_prev_out_idx);
static int s_find_utxo(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                        const char *a_token_ticker, uint256_t a_amount,
                        dap_chain_hash_fast_t *a_prev_hash, uint32_t *a_prev_out_idx,
                        uint256_t *a_input_value);
static int s_build_out_anon(const dap_chain_addr_t *a_addr, const char *a_token_ticker,
                            uint256_t a_amount, dap_chain_tx_out_anon_t *a_out,
                            const chipmunk_pedersen_params_t *a_params);

/*
 * Reject negative uint256 amounts.
 */
static bool s_amount_valid(uint256_t a_amount)
{
    if (compare256(a_amount, uint256_0) < 0) {
        log_it(L_ERROR, "Anonymous TX amount must be non-negative");
        return false;
    }
    return true;
}

/*
 * Wallet-level Chipmunk KI is signer-constant; mix in spent UTXO so each spend
 * commits a unique key image (multi anon TX from same wallet).
 */
static void s_bind_key_image_to_utxo(uint8_t *a_ki, size_t a_ki_size,
                                     const dap_chain_hash_fast_t *a_prev_hash,
                                     uint32_t a_prev_out_idx)
{
    if (!a_ki || !a_ki_size || !a_prev_hash)
        return;

    uint8_t l_raw[9216];
    size_t l_copy = a_ki_size < sizeof(l_raw) ? a_ki_size : sizeof(l_raw);
    memcpy(l_raw, a_ki, l_copy);

    uint8_t l_buf[sizeof(l_raw) + sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t)];
    size_t l_off = 0;
    memcpy(l_buf + l_off, l_raw, l_copy);
    l_off += l_copy;
    memcpy(l_buf + l_off, a_prev_hash, sizeof(dap_chain_hash_fast_t));
    l_off += sizeof(dap_chain_hash_fast_t);
    memcpy(l_buf + l_off, &a_prev_out_idx, sizeof(uint32_t));
    l_off += sizeof(uint32_t);

    dap_hash_sha3_256_raw(a_ki, l_buf, l_off);
    if (a_ki_size > sizeof(dap_hash_sha3_256_t))
        memset(a_ki + sizeof(dap_hash_sha3_256_t), 0, a_ki_size - sizeof(dap_hash_sha3_256_t));
}

static void s_uint256_to_bytes(uint256_t a_amount, uint8_t a_out[CHIPMUNK_PEDERSEN_VALUE_BYTES])
{
    memcpy(a_out, &a_amount, CHIPMUNK_PEDERSEN_VALUE_BYTES);
}

static int s_build_out_anon(const dap_chain_addr_t *a_addr, const char *a_token_ticker,
                            uint256_t a_amount, dap_chain_tx_out_anon_t *a_out,
                            const chipmunk_pedersen_params_t *a_params)
{
    if (!a_addr || !a_token_ticker || !a_out || !s_amount_valid(a_amount) || !a_params)
        return -EINVAL;

    uint8_t l_amount_bytes[CHIPMUNK_PEDERSEN_VALUE_BYTES];
    s_uint256_to_bytes(a_amount, l_amount_bytes);

    chipmunk_pedersen_commit_t l_commit;
    memset(&l_commit, 0, sizeof(l_commit));
    uint8_t l_rand[32];
    if (dap_random_bytes(l_rand, sizeof(l_rand)) != 0)
        return -EIO;

    if (chipmunk_pedersen_commit(&l_commit, a_params, l_amount_bytes, l_rand) != 0)
        return -EIO;

    chipmunk_range_proof_t l_rp;
    memset(&l_rp, 0, sizeof(l_rp));
    if (chipmunk_range_proof_prove(&l_rp, a_params, &l_commit, l_amount_bytes, l_rand) != 0)
        return -EIO;

    memset(a_out, 0, sizeof(*a_out));
    a_out->hdr.type = TX_ITEM_TYPE_OUT_ANON;
    a_out->hdr.version = 1;
    a_out->hdr.size = sizeof(*a_out);
    a_out->addr = *a_addr;
    memcpy(&a_out->commitment, &l_commit, sizeof(l_commit));
    memcpy(&a_out->range_proof, &l_rp, sizeof(l_rp));
    dap_strncpy(a_out->token_ticker, a_token_ticker, sizeof(a_out->token_ticker));
    return 0;
}

/* Build OUT_ANON with random blinding, returning the seed used.
 * Used by compose side to track blinding for Pedersen conservation. */
static int s_build_out_anon_tracked(const dap_chain_addr_t *a_addr, const char *a_token_ticker,
                                    uint256_t a_amount, dap_chain_tx_out_anon_t *a_out,
                                    const chipmunk_pedersen_params_t *a_params,
                                    uint8_t a_out_seed[32])
{
    if (!a_addr || !a_token_ticker || !a_out || !s_amount_valid(a_amount) || !a_params || !a_out_seed)
        return -EINVAL;

    uint8_t l_amount_bytes[CHIPMUNK_PEDERSEN_VALUE_BYTES];
    s_uint256_to_bytes(a_amount, l_amount_bytes);

    chipmunk_pedersen_commit_t l_commit;
    memset(&l_commit, 0, sizeof(l_commit));
    if (dap_random_bytes(a_out_seed, 32) != 0)
        return -EIO;

    if (chipmunk_pedersen_commit(&l_commit, a_params, l_amount_bytes, a_out_seed) != 0)
        return -EIO;

    chipmunk_range_proof_t l_rp;
    memset(&l_rp, 0, sizeof(l_rp));
    if (chipmunk_range_proof_prove(&l_rp, a_params, &l_commit, l_amount_bytes, a_out_seed) != 0)
        return -EIO;

    memset(a_out, 0, sizeof(*a_out));
    a_out->hdr.type = TX_ITEM_TYPE_OUT_ANON;
    a_out->hdr.version = 1;
    a_out->hdr.size = sizeof(*a_out);
    a_out->addr = *a_addr;
    memcpy(&a_out->commitment, &l_commit, sizeof(l_commit));
    memcpy(&a_out->range_proof, &l_rp, sizeof(l_rp));
    dap_strncpy(a_out->token_ticker, a_token_ticker, sizeof(a_out->token_ticker));
    return 0;
}

/* Build OUT_ANON with explicit blinding polynomials.
 * Used for the anchor output whose blinding closes the Pedersen gap. */
static int s_build_out_anon_explicit(const dap_chain_addr_t *a_addr, const char *a_token_ticker,
                                     uint256_t a_amount, dap_chain_tx_out_anon_t *a_out,
                                     const chipmunk_pedersen_params_t *a_params,
                                     const chipmunk_poly_t a_r[CHIPMUNK_LRS_K],
                                     const uint8_t a_rp_seed[32])
{
    if (!a_addr || !a_token_ticker || !a_out || !s_amount_valid(a_amount) || !a_params
        || !a_r || !a_rp_seed)
        return -EINVAL;

    uint8_t l_amount_bytes[CHIPMUNK_PEDERSEN_VALUE_BYTES];
    s_uint256_to_bytes(a_amount, l_amount_bytes);

    chipmunk_pedersen_commit_t l_commit;
    memset(&l_commit, 0, sizeof(l_commit));
    if (chipmunk_pedersen_commit_explicit(&l_commit, a_params, l_amount_bytes, a_r) != 0)
        return -EIO;

    chipmunk_range_proof_t l_rp;
    memset(&l_rp, 0, sizeof(l_rp));
    if (chipmunk_range_proof_prove_explicit(&l_rp, a_params, &l_commit, l_amount_bytes,
                                            a_r, a_rp_seed) != 0)
        return -EIO;

    memset(a_out, 0, sizeof(*a_out));
    a_out->hdr.type = TX_ITEM_TYPE_OUT_ANON;
    a_out->hdr.version = 1;
    a_out->hdr.size = sizeof(*a_out);
    a_out->addr = *a_addr;
    memcpy(&a_out->commitment, &l_commit, sizeof(l_commit));
    memcpy(&a_out->range_proof, &l_rp, sizeof(l_rp));
    dap_strncpy(a_out->token_ticker, a_token_ticker, sizeof(a_out->token_ticker));
    return 0;
}

/*
 * Generic anonymous transfer: works with any supported ring signature algorithm.
 * Algorithm is selected by wallet key type or explicit config.
 */
static dap_chain_datum_t *s_anon_transfer_generic(
    dap_chain_wallet_t *a_wallet,
    dap_chain_t *a_chain,
    const char *a_token_ticker,
    uint256_t a_amount,
    const dap_chain_addr_t *a_addr_to,
    const void *a_ring,
    size_t a_ring_size,
    const dap_chain_tx_anon_algo_t *a_algo,
    uint256_t a_fee,
    const dap_chain_addr_t *a_fee_addr,
    dap_chain_tx_anon_out_manifest_t *a_out_manifest)
{
    if (a_out_manifest)
        a_out_manifest->count = 0;
    if (!a_wallet || !a_chain || !a_token_ticker || !a_addr_to || !a_ring || !a_algo)
        return NULL;
    if (a_ring_size < CHIPMUNK_RING_N_MIN || a_ring_size > 64) return NULL;

    /* Resolve ledger and per-ledger anon context */
    dap_ledger_t *l_ledger_init = dap_ledger_by_net_name(a_chain->net_name);
    if (!l_ledger_init || !l_ledger_init->_internal) return NULL;
    dap_ledger_anon_ctx_t *l_anon_init = (dap_ledger_anon_ctx_t *)((dap_ledger_private_t *)l_ledger_init->_internal)->anon_data;
    if (!l_anon_init) return NULL;

    size_t pk_sz = a_algo->pk_size();
    lotrs_params_t l_par = { .d = 512, .q = 3168257, .k = 6, .l = 3 };

    /* 1. Get signer's key */
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    bool l_key_ok = l_key && l_key->type == a_algo->key_type;
    if (!l_key_ok && l_key && a_algo == &s_algo_lrs &&
        (l_key->type == DAP_ENC_KEY_TYPE_SIG_CHIPMUNK_LRS ||
         l_key->type == DAP_ENC_KEY_TYPE_SIG_CHIPMUNK_RING)) {
        l_key_ok = true;
    }
    if (!l_key_ok) {
        log_it(L_ERROR, "Wallet key type mismatch: expected %d, got %d",
               a_algo->key_type, l_key ? l_key->type : -1);
        if (l_key) dap_enc_key_delete(l_key);
        return NULL;
    }

    const void *l_sk = a_algo->get_sk(l_key);
    const void *l_pk = a_algo->get_pk(l_key);
    if (!l_sk || !l_pk) { dap_enc_key_delete(l_key); return NULL; }

    /* 2. Find signer in ring */
    uint32_t l_signer_idx = 0;
    int l_rc = s_find_signer_in_ring(a_algo, a_ring, a_ring_size, l_pk, &l_signer_idx);
    if (l_rc != 0) { dap_enc_key_delete(l_key); return NULL; }

    /* 3. SNARK witness */
    chipmunk_snark_witness_t l_witness;
    memset(&l_witness, 0, sizeof(l_witness));
    l_witness.signer_index = l_signer_idx;
    memset(&l_witness.indicator, 0, sizeof(l_witness.indicator));
    l_witness.indicator.coeffs[l_signer_idx] = 1;
    if (a_algo->populate_witness) {
        l_rc = a_algo->populate_witness(&l_witness, l_key);
        if (l_rc != 0) {
            log_it(L_ERROR, "Failed to populate SNARK witness for algo %s", a_algo->name);
            dap_enc_key_delete(l_key);
            return NULL;
        }
    }

    /* 4. UTXO — resolve ledger from chain's network name (before KI: bind KI per-UTXO) */
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_chain->net_name);
    if (!l_ledger) { dap_enc_key_delete(l_key); return NULL; }
    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(a_wallet, l_ledger->net_id);
    if (!l_wallet_addr) { dap_enc_key_delete(l_key); return NULL; }

    uint256_t l_required = a_amount;
    if (!IS_ZERO_256(a_fee)) {
        if (SUM_256_256(l_required, a_fee, &l_required)) {
            log_it(L_ERROR, "Anonymous TX amount + fee overflow");
            dap_enc_key_delete(l_key);
            DAP_DELETE(l_wallet_addr);
            return NULL;
        }
    }

    dap_chain_hash_fast_t l_prev_hash;
    uint32_t l_prev_idx = 0;
    uint256_t l_input_value = uint256_0;
    l_rc = s_find_utxo(l_ledger, l_wallet_addr, a_token_ticker, l_required,
                       &l_prev_hash, &l_prev_idx, &l_input_value);
    dap_chain_addr_t l_change_addr = *l_wallet_addr;
    DAP_DELETE(l_wallet_addr);
    if (l_rc != 0) { dap_enc_key_delete(l_key); return NULL; }

    /* 5. Key image bound to the specific UTXO (wallet-level KI is identical per signer) */
    uint8_t l_ki[9216];
    memset(l_ki, 0, sizeof(l_ki));
    l_rc = a_algo->key_image(l_ki, l_pk, l_sk, &l_par);
    if (l_rc != 0) { dap_enc_key_delete(l_key); return NULL; }
    s_bind_key_image_to_utxo(l_ki, sizeof(l_ki), &l_prev_hash, l_prev_idx);

    uint256_t l_spent = a_amount;
    if (!IS_ZERO_256(a_fee)) {
        if (SUM_256_256(l_spent, a_fee, &l_spent)) {
            log_it(L_ERROR, "Anonymous TX spent amount overflow");
            dap_enc_key_delete(l_key);
            return NULL;
        }
    }
    if (compare256(l_input_value, l_spent) < 0) {
        log_it(L_ERROR, "Insufficient UTXO value for anonymous transfer (need amount+fee)");
        dap_enc_key_delete(l_key);
        return NULL;
    }
    uint256_t l_change = uint256_0;
    if (compare256(l_input_value, l_spent) > 0)
        SUBTRACT_256_256(l_input_value, l_spent, &l_change);

    /* 6–7. Recipient OUT_ANON (Pedersen commitment + range proof) */
    if (!s_amount_valid(a_amount)) {
        dap_enc_key_delete(l_key);
        return NULL;
    }
    dap_chain_tx_out_anon_t l_out;
    uint8_t l_bob_seed[32];
    l_rc = s_build_out_anon_tracked(a_addr_to, a_token_ticker, a_amount, &l_out, &l_anon_init->pedersen_params, l_bob_seed);
    if (l_rc != 0) { dap_enc_key_delete(l_key); return NULL; }

    chipmunk_range_proof_t l_rp;
    memcpy(&l_rp, &l_out.range_proof, sizeof(l_rp));
    chipmunk_pedersen_commit_t l_commit;
    memcpy(&l_commit, &l_out.commitment, sizeof(l_commit));

    /* 8. Statement: message includes key image hash and range proof hash for cross-component binding */
    chipmunk_snark_statement_t l_statement;
    memset(&l_statement, 0, sizeof(l_statement));
    l_statement.ring = (const chipmunk_lrs_public_key_t *)a_ring;
    l_statement.ring_size = a_ring_size;

    dap_hash_sha3_256_t l_ki_hash;
    dap_hash_sha3_256_raw(l_ki_hash.raw, (const uint8_t *)l_ki, sizeof(l_ki));
    dap_hash_sha3_256_t l_rp_hash;
    dap_hash_sha3_256_raw(l_rp_hash.raw, (const uint8_t *)&l_rp, sizeof(l_rp));
    dap_hash_sha3_256_t l_commit_hash;
    dap_hash_sha3_256_raw(l_commit_hash.raw, (const uint8_t *)&l_commit, sizeof(l_commit));

    uint8_t l_msg_buf[sizeof(dap_chain_addr_t) + 32 + DAP_CHAIN_TICKER_SIZE_MAX + 32 + 32];
    ssize_t l_msg_size = dap_chain_anon_snark_build_message(l_msg_buf, sizeof(l_msg_buf),
                                                              a_addr_to, &l_commit_hash,
                                                              a_token_ticker, &l_ki_hash, &l_rp_hash);
    if (l_msg_size < 0)
        return NULL;
    l_statement.message = l_msg_buf;
    l_statement.message_size = (size_t)l_msg_size;

    /* 9. SNARK proof — use per-ledger anon context
     * The prover constructs:
     *   - indicator polynomial b (one-hot: b[signer]=1)
     *   - constraint polynomial z encoding ring membership (C3), binary (C1),
     *     single-signer (C2), and lattice binding (C4)
     *   - quotient polynomial q = z/(X-alpha)
     *   - FRI commitment layers (vestigial — verifier uses direct eval)
     * Ring membership is embedded in C3: sum(b_i*H(pk_i)) = H(pk_signer).
     * Verifier checks z(alpha)=0 via quotient relation at 11 random points. */
    chipmunk_snark_proof_t l_snark;
    memset(&l_snark, 0, sizeof(l_snark));
    l_rc = chipmunk_snark_prove(&l_snark, &l_anon_init->snark_ctx, &l_statement, &l_witness);
    dap_memwipe(&l_witness, sizeof(l_witness));
    if (l_rc != 0) { chipmunk_range_proof_free(&l_rp); dap_enc_key_delete(l_key); return NULL; }

    /* 10. Build TX */
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) { chipmunk_snark_proof_free(&l_snark); chipmunk_range_proof_free(&l_rp); dap_enc_key_delete(l_key); return NULL; }

    /* IN_ANON (variable-size: struct + ring public keys) */
    size_t l_ring_bytes = a_ring_size * pk_sz;
    size_t l_in_full_size = sizeof(dap_chain_tx_in_anon_t) + l_ring_bytes;
    uint8_t *l_in_buf = DAP_NEW_Z_SIZE(uint8_t, l_in_full_size);
    if (!l_in_buf) { chipmunk_snark_proof_free(&l_snark); chipmunk_range_proof_free(&l_rp); dap_enc_key_delete(l_key); return NULL; }
    dap_chain_tx_in_anon_t *l_in_ptr = (dap_chain_tx_in_anon_t *)l_in_buf;
    l_in_ptr->hdr.type = TX_ITEM_TYPE_IN_ANON; l_in_ptr->hdr.version = 1; l_in_ptr->hdr.size = l_in_full_size;
    l_in_ptr->prev_hash = l_prev_hash; l_in_ptr->prev_out_idx = l_prev_idx;
    l_in_ptr->ring_size = (uint32_t)a_ring_size;
    memcpy(&l_in_ptr->snark_proof, &l_snark, sizeof(l_snark));
    memcpy(l_in_ptr->key_image, l_ki, sizeof(l_ki));
    memcpy(l_in_buf + sizeof(dap_chain_tx_in_anon_t), a_ring, l_ring_bytes);
    dap_chain_datum_tx_add_item(&l_tx, l_in_buf);
    DAP_DELETE(l_in_buf);

    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_out);
    if (a_out_manifest && a_out_manifest->count < DAP_CHAIN_TX_ANON_OUT_MANIFEST_MAX)
        a_out_manifest->outs[a_out_manifest->count++] =
            (dap_chain_tx_anon_out_entry_t){ .addr = *a_addr_to, .value = a_amount, .out_idx = 0 };

    uint32_t l_out_idx = 1;
    uint8_t l_change_seed[32] = {};
    if (!IS_ZERO_256(l_change)) {
        dap_chain_tx_out_anon_t l_change_out;
        if (s_build_out_anon_tracked(&l_change_addr, a_token_ticker, l_change, &l_change_out, &l_anon_init->pedersen_params, l_change_seed) != 0) {
            chipmunk_snark_proof_free(&l_snark);
            chipmunk_range_proof_free(&l_rp);
            dap_chain_datum_tx_delete(l_tx);
            dap_enc_key_delete(l_key);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_change_out);
        if (a_out_manifest && a_out_manifest->count < DAP_CHAIN_TX_ANON_OUT_MANIFEST_MAX)
            a_out_manifest->outs[a_out_manifest->count++] =
                (dap_chain_tx_anon_out_entry_t){ .addr = l_change_addr, .value = l_change, .out_idx = l_out_idx };
        ++l_out_idx;
    }

    uint8_t l_fee_seed[32] = {};
    if (!IS_ZERO_256(a_fee)) {
        const dap_chain_addr_t *l_fee_dst = a_fee_addr;
        dap_chain_addr_t l_fee_blank = {};
        if (!l_fee_dst || dap_chain_addr_is_blank(l_fee_dst))
            l_fee_dst = &l_fee_blank;

        dap_chain_tx_out_anon_t l_fee_out;
        if (s_build_out_anon_tracked(l_fee_dst, a_token_ticker, a_fee, &l_fee_out, &l_anon_init->pedersen_params, l_fee_seed) != 0) {
            chipmunk_snark_proof_free(&l_snark);
            chipmunk_range_proof_free(&l_rp);
            dap_chain_datum_tx_delete(l_tx);
            dap_enc_key_delete(l_key);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_fee_out);
        if (a_out_manifest && a_out_manifest->count < DAP_CHAIN_TX_ANON_OUT_MANIFEST_MAX)
            a_out_manifest->outs[a_out_manifest->count++] =
                (dap_chain_tx_anon_out_entry_t){ .addr = *l_fee_dst, .value = a_fee, .out_idx = l_out_idx };
    }

    /* Anchor OUT_ANON: zero-value output whose blinding closes the Pedersen
     * conservation gap.  r_anchor = r_input - r_bob - r_change - r_fee.
     * Verify side reconstructs C_in(v_in, r_det) where r_det is derived from
     * the deterministic seed; sum(C_out) = A*(r_bob+r_change+r_fee+r_anchor)
     *                                    = A*r_det + encode(v_out_sum).
     * Since v_out_sum == v_in, conservation holds. */
    {
        uint8_t l_input_seed[32];
        dap_chain_anon_input_commit_seed(l_input_seed, &l_prev_hash, l_prev_idx);

        chipmunk_poly_t l_r_in[CHIPMUNK_LRS_K];
        if (chipmunk_pedersen_derive_blinding(l_r_in, l_input_seed) != 0) {
            chipmunk_snark_proof_free(&l_snark); chipmunk_range_proof_free(&l_rp);
            dap_chain_datum_tx_delete(l_tx); dap_enc_key_delete(l_key); return NULL;
        }

        chipmunk_poly_t l_r_sum[CHIPMUNK_LRS_K];
        memset(l_r_sum, 0, sizeof(l_r_sum));
        {
            chipmunk_poly_t l_r_tmp[CHIPMUNK_LRS_K];
            chipmunk_pedersen_derive_blinding(l_r_tmp, l_bob_seed);
            for (uint32_t j = 0; j < CHIPMUNK_LRS_K; ++j)
                chipmunk_poly_add_q(&l_r_sum[j], &l_r_sum[j], &l_r_tmp[j], (uint64_t)CHIPMUNK_Q);
        }
        if (!IS_ZERO_256(l_change)) {
            chipmunk_poly_t l_r_tmp[CHIPMUNK_LRS_K];
            chipmunk_pedersen_derive_blinding(l_r_tmp, l_change_seed);
            for (uint32_t j = 0; j < CHIPMUNK_LRS_K; ++j)
                chipmunk_poly_add_q(&l_r_sum[j], &l_r_sum[j], &l_r_tmp[j], (uint64_t)CHIPMUNK_Q);
        }
        if (!IS_ZERO_256(a_fee)) {
            chipmunk_poly_t l_r_tmp[CHIPMUNK_LRS_K];
            chipmunk_pedersen_derive_blinding(l_r_tmp, l_fee_seed);
            for (uint32_t j = 0; j < CHIPMUNK_LRS_K; ++j)
                chipmunk_poly_add_q(&l_r_sum[j], &l_r_sum[j], &l_r_tmp[j], (uint64_t)CHIPMUNK_Q);
        }

        chipmunk_poly_t l_r_anchor[CHIPMUNK_LRS_K];
        chipmunk_pedersen_blinding_sub(l_r_anchor, l_r_in, l_r_sum);

        /* Random seed for range-proof bit-level + Stern blinding */
        uint8_t l_anchor_rp_seed[32];
        if (dap_random_bytes(l_anchor_rp_seed, sizeof(l_anchor_rp_seed)) != 0) {
            chipmunk_snark_proof_free(&l_snark); chipmunk_range_proof_free(&l_rp);
            dap_chain_datum_tx_delete(l_tx); dap_enc_key_delete(l_key); return NULL;
        }
        dap_chain_addr_t l_anchor_addr = {};
        dap_chain_tx_out_anon_t l_anchor_out;
        if (s_build_out_anon_explicit(&l_anchor_addr, a_token_ticker, uint256_0,
                                         &l_anchor_out, &l_anon_init->pedersen_params,
                                         l_r_anchor, l_anchor_rp_seed) != 0) {
            chipmunk_snark_proof_free(&l_snark); chipmunk_range_proof_free(&l_rp);
            dap_chain_datum_tx_delete(l_tx); dap_enc_key_delete(l_key); return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_anchor_out);
    }

    /* KEY_IMAGE */
    dap_chain_tx_key_image_t l_ki_item;
    memset(&l_ki_item, 0, sizeof(l_ki_item));
    l_ki_item.hdr.type = TX_ITEM_TYPE_KEY_IMAGE; l_ki_item.hdr.version = 1; l_ki_item.hdr.size = sizeof(l_ki_item);
    memcpy(l_ki_item.image, l_ki, sizeof(l_ki));
    dap_hash_fast(l_ki, sizeof(l_ki), &l_ki_item.image_hash);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_ki_item);

    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, dap_chain_datum_tx_get_size(l_tx));

    chipmunk_snark_proof_free(&l_snark);
    chipmunk_range_proof_free(&l_rp);
    dap_enc_key_delete(l_key);

    log_it(L_INFO, "Anonymous TX created: algo=%s, ring=%zu", a_algo->name, a_ring_size);
    return l_datum;
}

/* --- Public API: algorithm from wallet key type --- */

dap_chain_datum_t *dap_chain_tx_anon_transfer(
    dap_chain_wallet_t *a_wallet,
    dap_chain_t *a_chain,
    const char *a_token_ticker,
    uint256_t a_amount,
    const dap_chain_addr_t *a_addr_to,
    const void *a_ring,
    size_t a_ring_size)
{
    /* Auto-detect algorithm from wallet key type */
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    if (!l_key) return NULL;
    dap_enc_key_type_t l_type = l_key->type;
    dap_enc_key_delete(l_key);

    const dap_chain_tx_anon_algo_t *l_algo = NULL;
    for (size_t i = 0; i < s_algo_count; ++i) {
        if (s_algos[i]->key_type == l_type) { l_algo = s_algos[i]; break; }
    }
    if (!l_algo) {
        log_it(L_ERROR, "No anonymous TX algorithm for key type %d", l_type);
        return NULL;
    }

    return s_anon_transfer_generic(a_wallet, a_chain, a_token_ticker, a_amount,
                                    a_addr_to, a_ring, a_ring_size, l_algo, uint256_0, NULL, NULL);
}

/* --- Public API: algorithm from config --- */

dap_chain_datum_t *dap_chain_tx_anon_transfer_with_algo(
    dap_chain_wallet_t *a_wallet,
    dap_chain_t *a_chain,
    const char *a_token_ticker,
    uint256_t a_amount,
    const dap_chain_addr_t *a_addr_to,
    const void *a_ring,
    size_t a_ring_size,
    const char *a_algo_name)
{
    const dap_chain_tx_anon_algo_t *l_algo = s_algo_find(a_algo_name);
    if (!l_algo) {
        log_it(L_ERROR, "Unknown anonymous TX algorithm: %s", a_algo_name);
        return NULL;
    }
    return s_anon_transfer_generic(a_wallet, a_chain, a_token_ticker, a_amount,
                                    a_addr_to, a_ring, a_ring_size, l_algo, uint256_0, NULL, NULL);
}

/* --- Auto-ring selection (algorithm-agnostic) --- */

static const dap_chain_tx_anon_algo_t *s_algo_pick_for_wallet(
    dap_enc_key_t *a_key, const char *a_cfg_algo_name)
{
    if (!a_key)
        return s_algo_find(a_cfg_algo_name);

    if (a_key->type == DAP_ENC_KEY_TYPE_SIG_CHIPMUNK_LRS)
        return s_algo_find("lrs");

    if (a_key->type == DAP_ENC_KEY_TYPE_SIG_CHIPMUNK_RING) {
        /* sig_chipmunk_ring wallets store native LRS key material */
        if (a_key->pub_key_data_size == sizeof(chipmunk_lrs_public_key_t))
            return s_algo_find("lrs");
        return s_algo_find("chipmunk_ring");
    }

    return s_algo_find(a_cfg_algo_name);
}

static int s_ring_add_member(uint8_t *a_ring, size_t *a_idx, size_t a_ring_cap,
                             const dap_chain_tx_anon_algo_t *a_algo,
                             const void *a_pk)
{
    if (!a_ring || !a_idx || !a_algo || !a_pk || *a_idx >= a_ring_cap)
        return -EINVAL;
    size_t l_pk_sz = a_algo->pk_size();
    memcpy(a_ring + (*a_idx) * l_pk_sz, a_pk, l_pk_sz);
    (*a_idx)++;
    return 0;
}

static int s_ring_fill_decoys(uint8_t *a_ring, size_t *a_idx, size_t a_ring_cap,
                              const dap_chain_tx_anon_algo_t *a_algo)
{
    if (!a_ring || !a_idx || !a_algo || *a_idx >= a_ring_cap)
        return -EINVAL;

    /* sig_chipmunk_ring wallets store LRS key material; synthetic decoys use LRS keygen */
    if (a_algo != &s_algo_lrs && a_algo != &s_algo_chipmunk_ring)
        return -ENOTSUP;

    while (*a_idx < a_ring_cap) {
        uint8_t l_seed[CHIPMUNK_LRS_SEED_BYTES];
        if (dap_random_bytes(l_seed, sizeof(l_seed)) != 0)
            return -EIO;

        chipmunk_lrs_public_key_t l_pk = {};
        chipmunk_lrs_secret_key_t l_sk = {};
        if (chipmunk_lrs_keypair_from_seeds(&l_pk, &l_sk, l_seed) != 0) {
            dap_memwipe(l_seed, sizeof(l_seed));
            return -EIO;
        }
        dap_memwipe(l_sk.x_seed, sizeof(l_sk.x_seed));
        dap_memwipe(l_seed, sizeof(l_seed));

        if (s_ring_add_member(a_ring, a_idx, a_ring_cap, a_algo, &l_pk) != 0)
            return -ENOMEM;
    }
    return 0;
}

dap_chain_datum_t *dap_chain_tx_anon_transfer_auto_ring(
    dap_chain_wallet_t *a_wallet,
    dap_chain_t *a_chain,
    const char *a_token_ticker,
    uint256_t a_amount,
    const dap_chain_addr_t *a_addr_to,
    size_t a_anon_set,
    uint256_t a_fee,
    dap_chain_tx_anon_out_manifest_t *a_out_manifest)
{
    if (!a_wallet || !a_chain || !a_token_ticker || !a_addr_to) return NULL;

    /* Verify ledger has anon context initialized */
    dap_ledger_t *l_ledger_check = dap_ledger_by_net_name(a_chain->net_name);
    if (!l_ledger_check || !l_ledger_check->_internal) return NULL;
    dap_ledger_anon_ctx_t *l_anon_check = (dap_ledger_anon_ctx_t *)((dap_ledger_private_t *)l_ledger_check->_internal)->anon_data;
    if (!l_anon_check) return NULL;

    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_chain->net_name);
    if (!l_ledger) return NULL;

    dap_enc_key_t *l_wallet_key = dap_chain_wallet_get_key(a_wallet, 0);
    if (!l_wallet_key) return NULL;

    /* Detect algorithm from wallet key type or config */
    const char *l_cfg_algo = "chipmunk_ring";
    dap_config_t *l_cfg = dap_config_open(a_chain->net_name);
    if (l_cfg) {
        const char *l_cfg_item = dap_config_get_item_str(l_cfg, "ledger", "anon_algo");
        if (l_cfg_item) l_cfg_algo = l_cfg_item;
        dap_config_close(l_cfg);
    }

    const dap_chain_tx_anon_algo_t *l_algo = s_algo_pick_for_wallet(l_wallet_key, l_cfg_algo);
    if (!l_algo) {
        log_it(L_ERROR, "Unknown anon_algo for wallet key type %d", l_wallet_key->type);
        dap_enc_key_delete(l_wallet_key);
        return NULL;
    }

    size_t pk_sz = l_algo->pk_size();
    const void *l_signer_pk = l_algo->get_pk(l_wallet_key);
    if (!l_signer_pk) {
        dap_enc_key_delete(l_wallet_key);
        return NULL;
    }

    if (a_anon_set < CHIPMUNK_RING_N_MIN)
        a_anon_set = CHIPMUNK_RING_N_MIN;
    if (a_anon_set > 64)
        a_anon_set = 64;

    uint8_t *l_ring = DAP_NEW_Z_SIZE(uint8_t, a_anon_set * pk_sz);
    if (!l_ring) {
        dap_enc_key_delete(l_wallet_key);
        return NULL;
    }

    /* P1-2 SECURITY FIX: Collect ALL decoys first, then insert signer at a
     * random position. The old code always placed the signer at index 0,
     * breaking anonymity (an observer knows position 0 is the real signer). */
    size_t l_idx = 0;

    /* Collect decoy pubkeys from stake validators (chipmunk keys only) */
    dap_list_t *l_validators = dap_chain_net_srv_stake_get_validators(a_chain->net_id, false, NULL);
    for (dap_list_t *it = l_validators; it && l_idx < a_anon_set - 1; it = it->next) {
        dap_chain_net_srv_stake_item_t *l_stake = (dap_chain_net_srv_stake_item_t *)it->data;
        if (!l_stake || !l_stake->pkey) continue;
        uint8_t l_pk_buf[4096];
        if (l_algo->pk_from_stake_pkey(l_pk_buf, l_stake->pkey) != 0)
            continue;
        if (l_algo->pk_cmp(l_pk_buf, l_signer_pk) == 0)
            continue;
        s_ring_add_member(l_ring, &l_idx, a_anon_set, l_algo, l_pk_buf);
    }
    dap_list_free_full(l_validators, NULL);

    if (l_idx < a_anon_set - 1 && s_ring_fill_decoys(l_ring, &l_idx, a_anon_set - 1, l_algo) != 0) {
        log_it(L_ERROR, "Failed to fill anonymous ring decoys (have %zu, need %zu)", l_idx, a_anon_set - 1);
        DAP_DELETE(l_ring);
        dap_enc_key_delete(l_wallet_key);
        return NULL;
    }

    /* Insert signer at a cryptographically random position in [0, a_anon_set).
     * Shift existing decoys to make room. This ensures the real signer's
     * position is uniformly random and unpredictable. */
    uint32_t l_signer_pos = 0;
    uint8_t l_rand_buf[4];
    if (dap_random_bytes(l_rand_buf, sizeof(l_rand_buf)) == 0)
        memcpy(&l_signer_pos, l_rand_buf, 4);
    l_signer_pos %= (uint32_t)a_anon_set;

    /* Shift decoys from [l_signer_pos, l_idx) one slot right to make room */
    if (l_signer_pos < l_idx) {
        memmove(l_ring + (l_signer_pos + 1) * pk_sz,
                l_ring + l_signer_pos * pk_sz,
                (l_idx - l_signer_pos) * pk_sz);
    }
    /* Place signer at the random position */
    memcpy(l_ring + l_signer_pos * pk_sz, l_signer_pk, pk_sz);
    l_idx = a_anon_set; /* ring is now full */

    if (l_idx < CHIPMUNK_RING_N_MIN) {
        DAP_DELETE(l_ring);
        dap_enc_key_delete(l_wallet_key);
        return NULL;
    }

    dap_chain_addr_t l_fee_addr = l_ledger->fee_addr;
    dap_chain_datum_t *l_datum = s_anon_transfer_generic(
        a_wallet, a_chain, a_token_ticker, a_amount, a_addr_to,
        l_ring, l_idx, l_algo, a_fee, &l_fee_addr, a_out_manifest);

    DAP_DELETE(l_ring);
    dap_enc_key_delete(l_wallet_key);
    return l_datum;
}

static void s_free_used_out_item(void *a_ptr)
{
    DAP_DELETE(a_ptr);
}

/*
 * Ledger scan fallback when wallet cache has no entry yet.
 * Uses OUT_ALL index (same as IN.tx_out_prev_idx semantics).
 */
static int s_find_utxo_ledger_scan(dap_ledger_t *a_ledger,
                                   const dap_chain_addr_t *a_addr,
                                   const char *a_token_ticker,
                                   uint256_t a_amount,
                                   dap_chain_hash_fast_t *a_prev_hash,
                                   uint32_t *a_prev_out_idx,
                                   uint256_t *a_input_value)
{
    dap_ledger_private_t *l_pvt = (dap_ledger_private_t *)a_ledger->_internal;
    dap_ledger_tx_item_t *l_item = NULL, *l_tmp = NULL;

    pthread_rwlock_rdlock(&l_pvt->ledger_rwlock);
    dap_ht_foreach(l_pvt->ledger_items, l_item, l_tmp) {
        if (!l_item->tx)
            continue;

        byte_t *l_tx_item = NULL;
        size_t l_item_size = 0;
        int l_out_idx = 0;

        TX_ITEM_ITER_TX(l_tx_item, l_item_size, l_item->tx) {
            bool l_candidate = false;
            uint256_t l_candidate_value = uint256_0;

            switch (*l_tx_item) {
            case TX_ITEM_TYPE_OUT_STD: {
                const dap_chain_tx_out_std_t *l_out = (const dap_chain_tx_out_std_t *)l_tx_item;
                if (dap_chain_addr_compare(&l_out->addr, a_addr) &&
                        !dap_strcmp(l_out->token, a_token_ticker) &&
                        compare256(l_out->value, a_amount) >= 0) {
                    l_candidate = true;
                    l_candidate_value = l_out->value;
                }
            } break;
            case TX_ITEM_TYPE_OUT_ANON: {
                const dap_chain_tx_out_anon_t *l_out = (const dap_chain_tx_out_anon_t *)l_tx_item;
                if (dap_chain_addr_compare(&l_out->addr, a_addr) &&
                        !dap_strcmp(l_out->token_ticker, a_token_ticker)) {
                    l_candidate = true;
                    l_candidate_value = a_amount;
                }
            } break;
            case TX_ITEM_TYPE_OUT_COND:
                ++l_out_idx;
                continue;
            default:
                continue;
            }

            if (l_candidate && !dap_ledger_tx_hash_is_used_out_item(a_ledger, &l_item->tx_hash_fast, l_out_idx, NULL)) {
                *a_prev_hash = l_item->tx_hash_fast;
                *a_prev_out_idx = (uint32_t)l_out_idx;
                if (a_input_value)
                    *a_input_value = l_candidate_value;
                pthread_rwlock_unlock(&l_pvt->ledger_rwlock);
                return 0;
            }
            ++l_out_idx;
        }
    }
    pthread_rwlock_unlock(&l_pvt->ledger_rwlock);
    return -ENOENT;
}

/*
 * Find a UTXO from wallet for spending.
 * Returns the previous TX hash and output index.
 */
static int s_find_utxo(dap_ledger_t *a_ledger,
                        const dap_chain_addr_t *a_addr,
                        const char *a_token_ticker,
                        uint256_t a_amount,
                        dap_chain_hash_fast_t *a_prev_hash,
                        uint32_t *a_prev_out_idx,
                        uint256_t *a_input_value)
{
    if (!a_ledger || !a_addr || !a_token_ticker || !a_prev_hash || !a_prev_out_idx)
        return -EINVAL;
    if (a_input_value)
        *a_input_value = uint256_0;

    dap_chain_net_t *l_net = dap_chain_net_by_id(a_ledger->net_id);
    if (l_net) {
        dap_list_t *l_outs = NULL;
        uint256_t l_transfer = uint256_0;
        int l_cache_rc = dap_chain_wallet_cache_tx_find_outs_with_val(
            l_net, a_token_ticker, a_addr, &l_outs, a_amount, &l_transfer);

        if (l_cache_rc == 0 && l_outs) {
            for (dap_list_t *l_it = l_outs; l_it; l_it = l_it->next) {
                dap_chain_tx_used_out_item_t *l_out = (dap_chain_tx_used_out_item_t *)l_it->data;
                if (l_out && compare256(l_out->value, a_amount) >= 0 &&
                        !dap_ledger_tx_hash_is_used_out_item(a_ledger, &l_out->tx_hash_fast,
                                                             (int)l_out->num_idx_out, NULL)) {
                    *a_prev_hash = l_out->tx_hash_fast;
                    *a_prev_out_idx = l_out->num_idx_out;
                    if (a_input_value)
                        *a_input_value = l_out->value;
                    dap_list_free_full(l_outs, s_free_used_out_item);
                    return 0;
                }
            }
            for (dap_list_t *l_it = l_outs; l_it; l_it = l_it->next) {
                dap_chain_tx_used_out_item_t *l_first = (dap_chain_tx_used_out_item_t *)l_it->data;
                if (!l_first)
                    continue;
                if (compare256(l_transfer, a_amount) >= 0 &&
                        !dap_ledger_tx_hash_is_used_out_item(a_ledger, &l_first->tx_hash_fast,
                                                             (int)l_first->num_idx_out, NULL)) {
                    *a_prev_hash = l_first->tx_hash_fast;
                    *a_prev_out_idx = l_first->num_idx_out;
                    if (a_input_value)
                        *a_input_value = l_first->value;
                    dap_list_free_full(l_outs, s_free_used_out_item);
                    return 0;
                }
            }
            dap_list_free_full(l_outs, s_free_used_out_item);
        } else if (l_cache_rc != 0) {
            log_it(L_DEBUG, "Wallet cache UTXO lookup failed (rc=%d), falling back to ledger scan", l_cache_rc);
        }
    }

    if (s_find_utxo_ledger_scan(a_ledger, a_addr, a_token_ticker, a_amount,
                                a_prev_hash, a_prev_out_idx, a_input_value) == 0)
        return 0;

    uint256_t l_balance = dap_ledger_calc_balance_full(a_ledger, a_addr, a_token_ticker);
    if (IS_ZERO_256(l_balance) || compare256(l_balance, a_amount) < 0) {
        log_it(L_ERROR, "Insufficient balance for anonymous transfer");
        return -ENODATA;
    }

    log_it(L_ERROR, "No suitable UTXO found for anonymous transfer");
    return -ENOENT;
}
/*
 * Reveal anonymous balance: scan ledger for OUT_ANON at address,
 * verify Pedersen commitment openings, sum unspent verified amounts.
 *
 * The user provides the amount and randomness seed. The ledger scans
 * all unspent OUT_ANON outputs at the address and verifies that
 * Com(amount; seed) matches the stored commitment. Matching outputs
 * are summed to produce the total verified balance.
 *
 * @param a_ledger The ledger.
 * @param a_addr Address to check.
 * @param a_token_ticker Token ticker.
 * @param a_randomness_seed Seed used when creating Pedersen commitments.
 * @param a_known_amount The amount the user claims to have committed.
 * @param a_balance_out Output: verified balance (sum of matching unspent outputs).
 * @return 0 on success, negative on error.
 */
int dap_chain_tx_anon_reveal_balance(dap_ledger_t *a_ledger,
                                      const dap_chain_addr_t *a_addr,
                                      const char *a_token_ticker,
                                      const uint8_t a_randomness_seed[32],
                                      uint256_t a_known_amount,
                                      uint256_t *a_balance_out)
{
    if (!a_ledger || !a_addr || !a_token_ticker || !a_randomness_seed || !a_balance_out)
        return -EINVAL;

    *a_balance_out = uint256_0;

    dap_ledger_private_t *l_pvt = (dap_ledger_private_t *)a_ledger->_internal;
    if (l_pvt->ledger_type != DAP_LEDGER_TYPE_ANON) {
        /* Non-anonymous ledger: use standard balance */
        *a_balance_out = dap_ledger_calc_balance(a_ledger, a_addr, a_token_ticker);
        return 0;
    }

    dap_ledger_anon_ctx_t *l_anon_ctx = (dap_ledger_anon_ctx_t *)l_pvt->anon_data;
    if (!l_anon_ctx) return -EINVAL;
    if (!s_amount_valid(a_known_amount)) return -EINVAL;

    /* Compute expected Pedersen commitment from known amount + seed */
    uint8_t l_amount_bytes[CHIPMUNK_PEDERSEN_VALUE_BYTES];
    s_uint256_to_bytes(a_known_amount, l_amount_bytes);

    chipmunk_pedersen_commit_t l_expected_commit;
    int rc = chipmunk_pedersen_commit(&l_expected_commit,
                                       &l_anon_ctx->pedersen_params,
                                       l_amount_bytes,
                                       (const uint8_t *)a_randomness_seed);
    if (rc != 0) {
        log_it(L_ERROR, "Failed to compute expected Pedersen commitment: %d", rc);
        return rc;
    }

    /* Scan ledger for unspent OUT_ANON at the address.
     * For each OUT_ANON matching address + token: compare commitment.
     * If commitment matches, the output is verified — add to balance. */
    uint256_t l_verified_balance = uint256_0;
    size_t l_verified_count = 0;

    /* Iterate all TXs in the ledger via the ledger items hash table */
    dap_ledger_tx_item_t *l_tx_item = NULL, *l_tmp = NULL;
    pthread_rwlock_rdlock(&l_pvt->ledger_rwlock);
    dap_ht_foreach(l_pvt->ledger_items, l_tx_item, l_tmp) {
        dap_chain_datum_tx_t *l_tx = l_tx_item->tx;
        if (!l_tx) continue;

        /* Check if this TX has been fully spent (n_outs_used == n_outs) */
        if (l_tx_item->cache_data.n_outs_used >= l_tx_item->cache_data.n_outs)
            continue;

        /* Iterate TX outputs looking for OUT_ANON at our address */
        uint32_t l_out_idx = 0;
        const uint8_t *l_item;
        size_t l_item_size;
        TX_ITEM_ITER_TX(l_item, l_item_size, l_tx) {
            if (*l_item == TX_ITEM_TYPE_OUT_ANON) {
                const dap_chain_tx_out_anon_t *l_out = (const dap_chain_tx_out_anon_t *)l_item;

                /* Match address and token ticker */
                if (dap_chain_addr_compare(&l_out->addr, a_addr) &&
                    !dap_strcmp(l_out->token_ticker, a_token_ticker)) {

                    /* Check if this output is already spent */
                    bool l_spent = false;
                    if (l_out_idx < l_tx_item->cache_data.n_outs) {
                        dap_hash_sha3_256_t l_zero_hash = {};
                        if (!dap_hash_fast_compare(&l_tx_item->out_metadata[l_out_idx].tx_spent_hash_fast, &l_zero_hash))
                            l_spent = true;
                    }

                    if (!l_spent) {
                        /* Compare commitment (copy from packed struct to avoid alignment issues) */
                        chipmunk_pedersen_commit_t l_stored_commit;
                        memcpy(&l_stored_commit, &l_out->commitment, sizeof(l_stored_commit));
                        if (dap_ledger_pedersen_commit_equal(&l_stored_commit, &l_expected_commit)) {
                            SUM_256_256(l_verified_balance, a_known_amount, &l_verified_balance);
                            l_verified_count++;
                        }
                    }
                }
                l_out_idx++;
            }
        }
    }
    pthread_rwlock_unlock(&l_pvt->ledger_rwlock);

    if (l_verified_count == 0) {
        log_it(L_WARNING, "No unspent OUT_ANON found at address with matching commitment");
        return -ENOENT;
    }

    *a_balance_out = l_verified_balance;

    log_it(L_INFO, "Anonymous balance revealed: %s (%zu matching outputs) for address",
           dap_uint256_to_const_char(l_verified_balance, NULL), l_verified_count);
    return 0;
}
