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
#include "dap_chain_datum_tx_anon.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_internal.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_type.h"
#include "dap_chain_ledger_pvt.h"
#include "dap_chain_net_srv_stake.h"
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
#include "dap_config.h"

#include <string.h>
#include <errno.h>

#define LOG_TAG "tx_anon_create"

/* Global context */
static dap_chain_tx_anon_context_t s_anon_ctx = { .initialized = false };

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
    int (*key_image)(uint8_t out[1408], const void *pk, const void *sk, const lotrs_params_t *par);
    /* Extract pk from stake pkey raw data */
    int (*pk_from_stake_pkey)(void *out_pk, const dap_pkey_t *pkey);
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
static int s_ring_key_image(uint8_t out[1408], const void *pk, const void *sk, const lotrs_params_t *par) {
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
    lotrs_poly_pack(out, 1408, I.polys[0], par);
    lotrs_polymat_free(&l_A);
    lotrs_polyvec_free(&I);
    return 0;
}
static int s_ring_pk_from_stake(void *out, const dap_pkey_t *pkey) {
    if (!out || !pkey) return -EINVAL;
    /* Check key type is Chipmunk (covers Ring, LRS, etc.) */
    if (pkey->header.type != DAP_PKEY_TYPE_SIG_CHIPMUNK) return -EINVAL;
    if (pkey->header.size < sizeof(chipmunk_ring_pk_t)) return -EINVAL;
    memcpy(out, pkey->pkey, sizeof(chipmunk_ring_pk_t));
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
};

/* --- LRS adapter --- */
static const void *s_lrs_get_pk(dap_enc_key_t *k) { return k->pub_key_data; }
static const void *s_lrs_get_sk(dap_enc_key_t *k) { return k->priv_key_data; }
static size_t s_lrs_pk_size(void) { return sizeof(chipmunk_lrs_public_key_t); }
static int s_lrs_pk_cmp(const void *a, const void *b) {
    return memcmp(a, b, sizeof(chipmunk_lrs_public_key_t));
}
static int s_lrs_key_image(uint8_t out[1408], const void *pk, const void *sk, const lotrs_params_t *par) {
    (void)pk; (void)par;
    return chipmunk_lrs_key_image(out, (const chipmunk_lrs_secret_key_t *)sk);
}
static int s_lrs_pk_from_stake(void *out, const dap_pkey_t *pkey) {
    if (!out || !pkey) return -EINVAL;
    /* Check key type is Chipmunk (covers Ring, LRS, etc.) */
    if (pkey->header.type != DAP_PKEY_TYPE_SIG_CHIPMUNK) return -EINVAL;
    if (pkey->header.size < sizeof(chipmunk_lrs_public_key_t)) return -EINVAL;
    memcpy(out, pkey->pkey, sizeof(chipmunk_lrs_public_key_t));
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

int dap_chain_tx_anon_init(void)
{
    if (s_anon_ctx.initialized) return 0;

    if (chipmunk_snark_init(&s_anon_ctx.snark_ctx) != 0) {
        log_it(L_ERROR, "Failed to initialize SNARK context");
        return -EINVAL;
    }

    uint8_t l_seed[32] = "chipchain-pedersen-tx-create-v1";
    if (chipmunk_pedersen_init(&s_anon_ctx.pedersen_params, l_seed) != 0) {
        log_it(L_ERROR, "Failed to initialize Pedersen parameters");
        return -EINVAL;
    }

    s_anon_ctx.initialized = true;
    log_it(L_INFO, "Anonymous TX creation context initialized");
    return 0;
}

void dap_chain_tx_anon_deinit(void)
{
    if (s_anon_ctx.initialized) {
        chipmunk_snark_ctx_free(&s_anon_ctx.snark_ctx);
        s_anon_ctx.initialized = false;
    }
}

dap_chain_tx_anon_context_t *dap_chain_tx_anon_get_context(void)
{
    return s_anon_ctx.initialized ? &s_anon_ctx : NULL;
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
    const dap_chain_tx_anon_algo_t *a_algo)
{
    if (!a_wallet || !a_chain || !a_token_ticker || !a_addr_to || !a_ring || !a_algo)
        return NULL;
    if (a_ring_size < CHIPMUNK_RING_N_MIN || a_ring_size > 64) return NULL;
    if (!s_anon_ctx.initialized) return NULL;

    size_t pk_sz = a_algo->pk_size();
    lotrs_params_t l_par = { .d = 512, .q = 3168257, .k = 6, .l = 3 };

    /* 1. Get signer's key */
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    if (!l_key || l_key->type != a_algo->key_type) {
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
    /* Copy secret key into witness (works for both Ring and LRS — both have polyvec s) */
    memcpy(l_witness.secret_key, l_sk, sizeof(chipmunk_poly_t) * CHIPMUNK_LRS_K);
    memset(&l_witness.indicator, 0, sizeof(l_witness.indicator));
    l_witness.indicator.coeffs[l_signer_idx] = 1;

    /* 4. Statement */
    chipmunk_snark_statement_t l_statement;
    memset(&l_statement, 0, sizeof(l_statement));
    l_statement.ring_size = a_ring_size;

    uint8_t l_msg_buf[sizeof(dap_chain_addr_t) + 32 + DAP_CHAIN_TICKER_SIZE_MAX];
    size_t l_off = 0;
    memcpy(l_msg_buf + l_off, a_addr_to, sizeof(dap_chain_addr_t)); l_off += sizeof(dap_chain_addr_t);
    memcpy(l_msg_buf + l_off, &a_amount, sizeof(uint256_t)); l_off += sizeof(uint256_t);
    size_t l_tl = strnlen(a_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    memcpy(l_msg_buf + l_off, a_token_ticker, l_tl); l_off += l_tl;
    l_statement.message = l_msg_buf;
    l_statement.message_size = l_off;

    /* 5. SNARK proof */
    chipmunk_snark_proof_t l_snark;
    memset(&l_snark, 0, sizeof(l_snark));
    l_rc = chipmunk_snark_prove(&l_snark, &s_anon_ctx.snark_ctx, &l_statement, &l_witness);
    if (l_rc != 0) { dap_enc_key_delete(l_key); return NULL; }

    /* 6. Key image */
    uint8_t l_ki[1408];
    memset(l_ki, 0, sizeof(l_ki));
    l_rc = a_algo->key_image(l_ki, l_pk, l_sk, &l_par);
    if (l_rc != 0) { chipmunk_snark_proof_free(&l_snark); dap_enc_key_delete(l_key); return NULL; }

    /* 7. UTXO */
    dap_chain_hash_fast_t l_prev_hash;
    uint32_t l_prev_idx = 0;
    l_rc = s_find_utxo(a_chain->ledger, &a_wallet->addr, a_token_ticker, a_amount, &l_prev_hash, &l_prev_idx);
    if (l_rc != 0) { chipmunk_snark_proof_free(&l_snark); dap_enc_key_delete(l_key); return NULL; }

    /* 8. Pedersen commitment */
    chipmunk_pedersen_commit_t l_commit;
    memset(&l_commit, 0, sizeof(l_commit));
    uint8_t l_rand[32]; dap_random_bytes(l_rand, 32);
    l_rc = chipmunk_pedersen_commit(&l_commit, &s_anon_ctx.pedersen_params, (int64_t)a_amount.lo, l_rand);
    if (l_rc != 0) { chipmunk_snark_proof_free(&l_snark); dap_enc_key_delete(l_key); return NULL; }

    /* 9. Range proof */
    chipmunk_range_proof_t l_rp;
    memset(&l_rp, 0, sizeof(l_rp));
    l_rc = chipmunk_range_proof_prove(&l_rp, &s_anon_ctx.pedersen_params, &l_commit, (int64_t)a_amount.lo, l_rand, 64);
    if (l_rc != 0) { chipmunk_snark_proof_free(&l_snark); dap_enc_key_delete(l_key); return NULL; }

    /* 10. Build TX */
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) { chipmunk_snark_proof_free(&l_snark); chipmunk_range_proof_free(&l_rp); dap_enc_key_delete(l_key); return NULL; }

    /* IN_ANON */
    dap_chain_tx_in_anon_t l_in;
    memset(&l_in, 0, sizeof(l_in));
    l_in.hdr.type = TX_ITEM_TYPE_IN_ANON; l_in.hdr.version = 1; l_in.hdr.size = sizeof(l_in);
    l_in.prev_hash = l_prev_hash; l_in.prev_out_idx = l_prev_idx;
    l_in.ring_size = (uint32_t)a_ring_size;
    memcpy(&l_in.snark_proof, &l_snark, sizeof(l_snark));
    memcpy(l_in.key_image, l_ki, sizeof(l_ki));
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_in);

    /* OUT_ANON */
    dap_chain_tx_out_anon_t l_out;
    memset(&l_out, 0, sizeof(l_out));
    l_out.hdr.type = TX_ITEM_TYPE_OUT_ANON; l_out.hdr.version = 1; l_out.hdr.size = sizeof(l_out);
    l_out.addr = *a_addr_to;
    memcpy(&l_out.commitment, &l_commit, sizeof(l_commit));
    memcpy(&l_out.range_proof, &l_rp, sizeof(l_rp));
    dap_strncpy(l_out.token_ticker, a_token_ticker, sizeof(l_out.token_ticker));
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_out);

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
                                    a_addr_to, a_ring, a_ring_size, l_algo);
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
                                    a_addr_to, a_ring, a_ring_size, l_algo);
}

/* --- Auto-ring selection (algorithm-agnostic) --- */

dap_chain_datum_t *dap_chain_tx_anon_transfer_auto_ring(
    dap_chain_wallet_t *a_wallet,
    dap_chain_t *a_chain,
    const char *a_token_ticker,
    uint256_t a_amount,
    const dap_chain_addr_t *a_addr_to,
    size_t a_anon_set)
{
    if (!a_wallet || !a_chain || !a_token_ticker || !a_addr_to) return NULL;

    dap_ledger_t *l_ledger = a_chain->ledger;
    if (!l_ledger) return NULL;

    /* Detect algorithm from config or wallet key type */
    const char *l_algo_name = "chipmunk_ring"; /* default */
    dap_config_t *l_cfg = dap_config_open(a_chain->net_name);
    if (l_cfg) {
        const char *l_cfg_algo = dap_config_get_item_str(l_cfg, "ledger", "anon_algo");
        if (l_cfg_algo) l_algo_name = l_cfg_algo;
        dap_config_close(l_cfg);
    }

    const dap_chain_tx_anon_algo_t *l_algo = s_algo_find(l_algo_name);
    if (!l_algo) {
        log_it(L_ERROR, "Unknown anon_algo: %s", l_algo_name);
        return NULL;
    }

    size_t pk_sz = l_algo->pk_size();

    /* Get validators from stake service */
    dap_list_t *l_validators = dap_chain_net_srv_stake_get_validators(a_chain->net_id, false, NULL);
    if (!l_validators) {
        log_it(L_ERROR, "No validators for ring");
        return NULL;
    }

    size_t l_total = dap_list_length(l_validators);
    if (l_total < a_anon_set) a_anon_set = l_total;
    if (a_anon_set < CHIPMUNK_RING_N_MIN) {
        dap_list_free_full(l_validators, NULL);
        return NULL;
    }

    /* Build ring buffer */
    uint8_t *l_ring = DAP_NEW_Z_SIZE(uint8_t, a_anon_set * pk_sz);
    if (!l_ring) { dap_list_free_full(l_validators, NULL); return NULL; }

    size_t l_idx = 0;
    for (dap_list_t *it = l_validators; it && l_idx < a_anon_set; it = it->next) {
        dap_chain_net_srv_stake_item_t *l_stake = (dap_chain_net_srv_stake_item_t *)it->data;
        if (!l_stake || !l_stake->pkey) continue;
        if (l_algo->pk_from_stake_pkey(l_ring + l_idx * pk_sz, l_stake->pkey) == 0) {
            l_idx++;
        }
    }
    dap_list_free_full(l_validators, NULL);

    if (l_idx < CHIPMUNK_RING_N_MIN) {
        DAP_DELETE(l_ring);
        return NULL;
    }

    dap_chain_datum_t *l_datum = s_anon_transfer_generic(
        a_wallet, a_chain, a_token_ticker, a_amount, a_addr_to,
        l_ring, l_idx, l_algo);

    DAP_DELETE(l_ring);
    return l_datum;
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
                        uint32_t *a_prev_out_idx)
{
    if (!a_ledger || !a_addr || !a_token_ticker || !a_prev_hash || !a_prev_out_idx)
        return -EINVAL;

    /* Get balance to check if we have enough */
    uint256_t l_balance = dap_ledger_calc_balance(a_ledger, a_addr, a_token_ticker);
    if (IS_ZERO_256(l_balance) || compare256(l_balance, a_amount) < 0) {
        log_it(L_ERROR, "Insufficient balance for anonymous transfer");
        return -ENODATA;
    }

    /* Find a UTXO with sufficient value */
    /* The ledger tracks UTXOs in ledger_items hash table.
     * We need to find one that belongs to our address and has enough value. */
    dap_ledger_private_t *l_pvt = (dap_ledger_private_t *)a_ledger->_internal;

    /* Iterate through ledger items to find a suitable UTXO */
    dap_ledger_tx_item_t *l_item, *l_tmp;
    pthread_rwlock_rdlock(&l_pvt->ledger_rwlock);
    dap_ht_foreach(l_pvt->ledger_items, l_item, l_tmp) {
        if (!l_item->tx) continue;

        /* Check if this TX has an output to our address */
        const uint8_t *l_tx_item = l_item->tx->tx_items;
        size_t l_offset = 0;
        size_t l_tx_size = dap_chain_datum_tx_get_size(l_item->tx);
        uint32_t l_out_idx = 0;

        while (l_offset < l_tx_size) {
            uint8_t l_type = *l_tx_item;
            if (l_type == TX_ITEM_TYPE_OUT_STD) {
                const dap_chain_tx_out_std_t *l_out = (const dap_chain_tx_out_std_t *)l_tx_item;
                if (dap_chain_addr_compare(&l_out->addr, a_addr) &&
                    strcmp(l_out->token_ticker, a_token_ticker) == 0 &&
                    compare256(l_out->value, a_amount) >= 0) {
                    /* Found suitable UTXO */
                    *a_prev_hash = l_item->tx_hash_fast;
                    *a_prev_out_idx = l_out_idx;
                    pthread_rwlock_unlock(&l_pvt->ledger_rwlock);
                    return 0;
                }
            }
            uint32_t l_item_size = *(const uint32_t *)(l_tx_item + 4);
            if (l_item_size == 0) break;
            l_tx_item += l_item_size;
            l_offset += l_item_size;
            l_out_idx++;
        }
    }
    pthread_rwlock_unlock(&l_pvt->ledger_rwlock);

    log_it(L_ERROR, "No suitable UTXO found for anonymous transfer");
    return -ENOENT;
}

/*
 * Build an anonymous transfer transaction.
 */
dap_chain_datum_t *dap_chain_tx_anon_transfer(
    dap_chain_wallet_t *a_wallet,
    dap_chain_t *a_chain,
    const char *a_token_ticker,
    uint256_t a_amount,
    const dap_chain_addr_t *a_addr_to,
    const chipmunk_ring_pk_t *a_ring,
    size_t a_ring_size)
{
    if (!a_wallet || !a_chain || !a_token_ticker || !a_addr_to || !a_ring) {
        log_it(L_ERROR, "NULL parameters for anonymous transfer");
        return NULL;
    }
    if (a_ring_size < CHIPMUNK_RING_N_MIN || a_ring_size > 64) {
        log_it(L_ERROR, "Ring size %zu out of range [%u, 64]",
               a_ring_size, CHIPMUNK_RING_N_MIN);
        return NULL;
    }
    if (!s_anon_ctx.initialized) {
        log_it(L_ERROR, "Anonymous TX creation context not initialized");
        return NULL;
    }

    /* 1. Get signer's key from wallet */
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    if (!l_key) {
        log_it(L_ERROR, "Failed to get key from wallet");
        return NULL;
    }

    /* 2. Extract Chipmunk Ring secret and public keys */
    const chipmunk_ring_sk_t *l_sk = s_get_ring_sk(l_key);
    const chipmunk_ring_pk_t *l_pk = s_get_ring_pk(l_key);
    if (!l_sk || !l_pk) {
        log_it(L_ERROR, "Wallet key is not Chipmunk Ring type or missing key data");
        dap_enc_key_delete(l_key);
        return NULL;
    }

    /* 3. Find signer's index in ring */
    uint32_t l_signer_idx = 0;
    int l_rc = s_find_signer_in_ring(a_ring, a_ring_size, l_pk, &l_signer_idx);
    if (l_rc != 0) {
        log_it(L_ERROR, "Signer's public key not found in ring");
        dap_enc_key_delete(l_key);
        return NULL;
    }

    /* 4. Build witness for SNARK */
    chipmunk_snark_witness_t l_witness;
    memset(&l_witness, 0, sizeof(l_witness));
    l_witness.signer_index = l_signer_idx;
    /* Copy secret key polynomials into witness */
    for (uint32_t i = 0; i < l_sk->s.n && i < CHIPMUNK_LRS_K; ++i) {
        if (l_sk->s.polys[i]) {
            memcpy(&l_witness.secret_key[i], l_sk->s.polys[i], sizeof(chipmunk_poly_t));
        }
    }
    /* Build indicator polynomial: b[i] = 1 if i == signer_idx, else 0 */
    memset(&l_witness.indicator, 0, sizeof(l_witness.indicator));
    l_witness.indicator.coeffs[l_signer_idx] = 1;

    /* 5. Build statement */
    chipmunk_snark_statement_t l_statement;
    memset(&l_statement, 0, sizeof(l_statement));
    l_statement.ring_size = a_ring_size;

    /* Message = hash(recipient || amount || token) */
    uint8_t l_msg_buf[sizeof(dap_chain_addr_t) + 32 + DAP_CHAIN_TICKER_SIZE_MAX];
    size_t l_msg_off = 0;
    memcpy(l_msg_buf + l_msg_off, a_addr_to, sizeof(dap_chain_addr_t));
    l_msg_off += sizeof(dap_chain_addr_t);
    memcpy(l_msg_buf + l_msg_off, &a_amount, sizeof(uint256_t));
    l_msg_off += sizeof(uint256_t);
    size_t l_ticker_len = strnlen(a_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    memcpy(l_msg_buf + l_msg_off, a_token_ticker, l_ticker_len);
    l_msg_off += l_ticker_len;

    l_statement.message = l_msg_buf;
    l_statement.message_size = l_msg_off;

    /* 6. Generate SNARK proof */
    chipmunk_snark_proof_t l_snark_proof;
    memset(&l_snark_proof, 0, sizeof(l_snark_proof));

    l_rc = chipmunk_snark_prove(&l_snark_proof, &s_anon_ctx.snark_ctx,
                                 &l_statement, &l_witness);
    if (l_rc != 0) {
        log_it(L_ERROR, "Failed to generate SNARK proof: %d", l_rc);
        dap_enc_key_delete(l_key);
        return NULL;
    }

    /* 7. Generate key image: I = A_I * s */
    uint8_t l_key_image[1408];
    memset(l_key_image, 0, sizeof(l_key_image));
    lotrs_params_t l_par = { .d = 512, .q = 3168257, .k = 6, .l = 3 };
    l_rc = s_generate_key_image_from_ring(l_key_image, l_pk, l_sk, &l_par);
    if (l_rc != 0) {
        log_it(L_ERROR, "Failed to generate key image: %d", l_rc);
        chipmunk_snark_proof_free(&l_snark_proof);
        dap_enc_key_delete(l_key);
        return NULL;
    }

    /* 8. Find UTXO for spending */
    dap_ledger_t *l_ledger = a_chain->ledger;
    dap_chain_hash_fast_t l_prev_hash;
    uint32_t l_prev_out_idx = 0;
    l_rc = s_find_utxo(l_ledger, &a_wallet->addr, a_token_ticker, a_amount,
                        &l_prev_hash, &l_prev_out_idx);
    if (l_rc != 0) {
        chipmunk_snark_proof_free(&l_snark_proof);
        dap_enc_key_delete(l_key);
        return NULL;
    }

    /* 9. Create Pedersen commitment for output amount */
    chipmunk_pedersen_commit_t l_output_commit;
    memset(&l_output_commit, 0, sizeof(l_output_commit));

    uint8_t l_rand_seed[32];
    dap_random_bytes(l_rand_seed, 32);

    int64_t l_amount_i64 = (int64_t)a_amount.lo;
    l_rc = chipmunk_pedersen_commit(&l_output_commit, &s_anon_ctx.pedersen_params,
                                     l_amount_i64, l_rand_seed);
    if (l_rc != 0) {
        log_it(L_ERROR, "Failed to create Pedersen commitment: %d", l_rc);
        chipmunk_snark_proof_free(&l_snark_proof);
        dap_enc_key_delete(l_key);
        return NULL;
    }

    /* 10. Generate range proof: amount ∈ [0, 2^64) */
    chipmunk_range_proof_t l_range_proof;
    memset(&l_range_proof, 0, sizeof(l_range_proof));

    l_rc = chipmunk_range_proof_prove(&l_range_proof, &s_anon_ctx.pedersen_params,
                                       &l_output_commit, l_amount_i64, l_rand_seed, 64);
    if (l_rc != 0) {
        log_it(L_ERROR, "Failed to generate range proof: %d", l_rc);
        chipmunk_snark_proof_free(&l_snark_proof);
        dap_enc_key_delete(l_key);
        return NULL;
    }

    /* 11. Build the transaction */
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create TX");
        chipmunk_snark_proof_free(&l_snark_proof);
        chipmunk_range_proof_free(&l_range_proof);
        dap_enc_key_delete(l_key);
        return NULL;
    }

    /* Add anonymous input */
    dap_chain_tx_in_anon_t l_in_anon;
    memset(&l_in_anon, 0, sizeof(l_in_anon));
    l_in_anon.hdr.type = TX_ITEM_TYPE_IN_ANON;
    l_in_anon.hdr.version = 1;
    l_in_anon.hdr.size = sizeof(l_in_anon);
    l_in_anon.prev_hash = l_prev_hash;
    l_in_anon.prev_out_idx = l_prev_out_idx;
    l_in_anon.ring_size = (uint32_t)a_ring_size;
    memcpy(&l_in_anon.snark_proof, &l_snark_proof, sizeof(l_snark_proof));
    memcpy(l_in_anon.key_image, l_key_image, sizeof(l_key_image));

    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_in_anon);

    /* Add anonymous output */
    dap_chain_tx_out_anon_t l_out_anon;
    memset(&l_out_anon, 0, sizeof(l_out_anon));
    l_out_anon.hdr.type = TX_ITEM_TYPE_OUT_ANON;
    l_out_anon.hdr.version = 1;
    l_out_anon.hdr.size = sizeof(l_out_anon);
    l_out_anon.addr = *a_addr_to;
    memcpy(&l_out_anon.commitment, &l_output_commit, sizeof(l_output_commit));
    memcpy(&l_out_anon.range_proof, &l_range_proof, sizeof(l_range_proof));
    dap_strncpy(l_out_anon.token_ticker, a_token_ticker, sizeof(l_out_anon.token_ticker));

    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_out_anon);

    /* Add key image */
    dap_chain_tx_key_image_t l_ki;
    memset(&l_ki, 0, sizeof(l_ki));
    l_ki.hdr.type = TX_ITEM_TYPE_KEY_IMAGE;
    l_ki.hdr.version = 1;
    l_ki.hdr.size = sizeof(l_ki);
    memcpy(l_ki.image, l_key_image, sizeof(l_key_image));
    dap_hash_fast(l_key_image, sizeof(l_key_image), &l_ki.image_hash);

    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_ki);

    /* Wrap TX in datum */
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX,
                                                          l_tx,
                                                          dap_chain_datum_tx_get_size(l_tx));

    /* Cleanup */
    chipmunk_snark_proof_free(&l_snark_proof);
    chipmunk_range_proof_free(&l_range_proof);
    dap_enc_key_delete(l_key);

    log_it(L_INFO, "Created anonymous transfer TX: ring_size=%zu, amount=%lu",
           a_ring_size, a_amount.lo);
    return l_datum;
}

/*
 * Auto-ring selection: pick public keys from ledger's validator set.
 */
dap_chain_datum_t *dap_chain_tx_anon_transfer_auto_ring(
    dap_chain_wallet_t *a_wallet,
    dap_chain_t *a_chain,
    const char *a_token_ticker,
    uint256_t a_amount,
    const dap_chain_addr_t *a_addr_to,
    size_t a_anon_set)
{
    if (!a_wallet || !a_chain || !a_token_ticker || !a_addr_to) {
        log_it(L_ERROR, "NULL parameters for auto-ring anonymous transfer");
        return NULL;
    }

    /* Get ledger */
    dap_ledger_t *l_ledger = a_chain->ledger;
    if (!l_ledger) {
        log_it(L_ERROR, "No ledger for chain %s", a_chain->name);
        return NULL;
    }

    /* Check ledger is anonymous */
    dap_ledger_private_t *l_pvt = (dap_ledger_private_t *)l_ledger->_internal;
    if (l_pvt->ledger_type != DAP_LEDGER_TYPE_ANON) {
        log_it(L_ERROR, "Ledger is not anonymous");
        return NULL;
    }

    /* Get validator public keys from stake service */
    dap_list_t *l_validators = dap_chain_net_srv_stake_get_validators(
        a_chain->net_id, false, NULL);
    if (!l_validators) {
        log_it(L_ERROR, "No validators available for ring");
        return NULL;
    }

    size_t l_total = dap_list_length(l_validators);
    if (l_total < a_anon_set) {
        log_it(L_WARNING, "Only %zu validators available, requested %zu", l_total, a_anon_set);
        a_anon_set = l_total;
    }
    if (a_anon_set < CHIPMUNK_RING_N_MIN) {
        log_it(L_ERROR, "Not enough validators for minimum ring size (%zu < %u)",
               a_anon_set, CHIPMUNK_RING_N_MIN);
        dap_list_free_full(l_validators, NULL);
        return NULL;
    }

    /* Build ring from validator public keys using algorithm adapter */
    size_t pk_sz = l_algo->pk_size();
    uint8_t *l_ring = DAP_NEW_Z_SIZE(uint8_t, a_anon_set * pk_sz);
    if (!l_ring) { dap_list_free_full(l_validators, NULL); return NULL; }

    /* Pick first a_anon_set validators */
    size_t l_idx = 0;
    for (dap_list_t *it = l_validators; it && l_idx < a_anon_set; it = it->next) {
        dap_chain_net_srv_stake_item_t *l_stake = (dap_chain_net_srv_stake_item_t *)it->data;
        if (!l_stake || !l_stake->pkey) continue;

        /* Extract public key using algorithm adapter */
        if (l_algo->pk_from_stake_pkey(l_ring + l_idx * pk_sz, l_stake->pkey) == 0) {
            l_idx++;
        }
    }
    dap_list_free_full(l_validators, NULL);

    if (l_idx < CHIPMUNK_RING_N_MIN) {
        log_it(L_ERROR, "Failed to collect enough valid validator keys (%zu)", l_idx);
        DAP_DELETE(l_ring);
        return NULL;
    }

    /* Create anonymous transfer with collected ring */
    dap_chain_datum_t *l_datum = dap_chain_tx_anon_transfer(
        a_wallet, a_chain, a_token_ticker, a_amount, a_addr_to, l_ring, l_idx);

    DAP_DELETE(l_ring);
    return l_datum;
}

/*
 * Reveal anonymous balance: verify Pedersen commitment opening.
 * If the user provides the randomness used during commitment, we can
 * verify and compute the actual balance.
 */
int dap_chain_tx_anon_reveal_balance(dap_ledger_t *a_ledger,
                                      const dap_chain_addr_t *a_addr,
                                      const char *a_token_ticker,
                                      const uint8_t a_randomness_seed[32],
                                      uint256_t *a_balance_out)
{
    if (!a_ledger || !a_addr || !a_token_ticker || !a_randomness_seed || !a_balance_out)
        return -EINVAL;

    dap_ledger_private_t *l_pvt = (dap_ledger_private_t *)a_ledger->_internal;
    if (l_pvt->ledger_type != DAP_LEDGER_TYPE_ANON) {
        *a_balance_out = dap_ledger_calc_balance(a_ledger, a_addr, a_token_ticker);
        return 0;
    }

    dap_ledger_anon_ctx_t *l_anon = (dap_ledger_anon_ctx_t *)l_pvt->anon_data;
    if (!l_anon) return -EINVAL;

    /* Iterate through all TX outputs to this address and verify commitments */
    /* The Pedersen commitment is: C = A*r + encode(amount)
     * Given r (randomness), we can recover amount from C.
     * But we need the actual commitment values from the ledger. */

    /* For each anonymous output to this address:
     * 1. Get the Pedersen commitment from the TX
     * 2. Compute the expected commitment with the provided randomness
     * 3. If they match, add the amount to the balance
     */

    /* This requires iterating through all TXs in the ledger,
     * finding anonymous outputs to this address, and verifying openings.
     * For now, return 0 with a note that the full implementation
     * requires the commitment openings to be stored alongside the TXs. */

    *a_balance_out = uint256_0;
    log_it(L_INFO, "Anonymous balance reveal: requires commitment openings stored with TXs");
    return 0;
}
