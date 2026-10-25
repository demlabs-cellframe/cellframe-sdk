/*
 *
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.net>
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
#include "dap_pkey.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_net_decree.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_http_ban_list_client.h"
#include "dap_chain_policy.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_snapshot.h"
#include "dap_string.h"



#define LOG_TAG "chain_net_decree"


// private types definition
typedef struct decree_table {
    dap_hash_fast_t key;
    bool wait_for_apply, is_applied;
    dap_chain_datum_decree_t *decree;
    UT_hash_handle hh;
} decree_table_t;

// Private variable

// Decrees of a subtype/type this build does not recognize. They are accepted (see
// the default branches below) so that an upgrade can make them effective without a
// full chain scan; the counter keeps them visible in diagnostics.
static _Atomic uint64_t s_unknown_decree_count;

uint64_t dap_chain_net_decree_unknown_count(void)
{
    return atomic_load(&s_unknown_decree_count);
}

/* *** Decree journal (snapshot section "decree_journal") ***
 * The decree table itself is in-memory only: it is built by walking the chain.
 * A snapshot-based start walks no datums, so without this section every decree
 * effect that has no dedicated section of its own (esbocs consensus version and
 * its strict-era boundary, min validators, fee, rewards, bans) is lost, and a
 * decree carrying a subtype this build does not know could never become
 * effective after an upgrade without a full rescan.
 *
 * The section stores the decree datums themselves, in chain order. Loading
 * replays each one through the ordinary load path, i.e. with the CURRENT binary:
 * an unknown subtype is recorded (see the default branch of the common handler)
 * and applied as soon as a build understands it, while known ones re-apply
 * idempotently (decree table -123, policy -4, anchor -111).
 */
#define DAP_NET_DECREE_JOURNAL_SECTION "decree_journal"
#define DAP_NET_DECREE_JOURNAL_VERSION 1

typedef struct DAP_ALIGN_PACKED s_decree_journal_hdr {
    uint32_t version;
    uint32_t reserved;
    uint64_t net_id;
    uint64_t count;
} s_decree_journal_hdr_t;

typedef struct DAP_ALIGN_PACKED s_decree_journal_rec {
    uint64_t size;      // decree datum size in bytes
    uint8_t applied;     // it was effective when the snapshot was taken
    uint8_t reserved[7];
} s_decree_journal_rec_t;

static int s_decree_journal_cmp(const void *a_a, const void *a_b)
{
    const dap_chain_datum_decree_t *l_a = *(const dap_chain_datum_decree_t **)a_a;
    const dap_chain_datum_decree_t *l_b = *(const dap_chain_datum_decree_t **)a_b;
    if (l_a->header.ts_created != l_b->header.ts_created)
        return l_a->header.ts_created < l_b->header.ts_created ? -1 : 1;
    return 0;
}

static int s_decree_journal_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out)
{
    (void)a_ctx;
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){ .uint64 = a_net_id });
    if (!l_net)
        return 0;   // nothing to store for a net we do not have
    decree_table_t **l_decrees = dap_chain_net_get_decrees(l_net);
    if (!l_decrees)
        return 0;
    size_t l_count = 0;
    for (decree_table_t *l_it = *l_decrees; l_it; l_it = l_it->hh.next)
        if (l_it->decree)
            ++l_count;
    if (!l_count)
        return 0;
    // Chain order, not hash order: some decrees adjust values that others set
    // (fee, owners, consensus version), so the replay must follow the chain.
    dap_chain_datum_decree_t **l_sorted = DAP_NEW_Z_COUNT(dap_chain_datum_decree_t *, l_count);
    if (!l_sorted)
        return -2;
    size_t l_n = 0;
    for (decree_table_t *l_it = *l_decrees; l_it; l_it = l_it->hh.next)
        if (l_it->decree)
            l_sorted[l_n++] = l_it->decree;
    qsort(l_sorted, l_n, sizeof(dap_chain_datum_decree_t *), s_decree_journal_cmp);
    s_decree_journal_hdr_t l_hdr = { .version = DAP_NET_DECREE_JOURNAL_VERSION,
            .net_id = a_net_id, .count = l_n };
    int l_ret = 0;
    if (!dap_string_append_len(a_out, (const char *)&l_hdr, sizeof(l_hdr)))
        l_ret = -2;
    for (size_t i = 0; i < l_n && !l_ret; ++i) {
        size_t l_size = dap_chain_datum_decree_get_size(l_sorted[i]);
        s_decree_journal_rec_t l_rec = { .size = l_size, .applied = 1 };
        if (!l_size || !dap_string_append_len(a_out, (const char *)&l_rec, sizeof(l_rec))
                || !dap_string_append_len(a_out, (const char *)l_sorted[i], l_size))
            l_ret = -2;
    }
    DAP_DELETE(l_sorted);
    return l_ret;
}

static int s_decree_journal_load(void *a_ctx, const uint8_t *a_data, size_t a_size)
{
    (void)a_ctx;
    if (!a_data || a_size < sizeof(s_decree_journal_hdr_t))
        return -1;
    s_decree_journal_hdr_t l_hdr;
    memcpy(&l_hdr, a_data, sizeof(l_hdr));
    if (l_hdr.version != DAP_NET_DECREE_JOURNAL_VERSION) {
        log_it(L_WARNING, "Decree journal: unsupported format version %u (this build understands %u)",
               l_hdr.version, DAP_NET_DECREE_JOURNAL_VERSION);
        return -2;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){ .uint64 = l_hdr.net_id });
    if (!l_net)
        return -3;
    // The decrees were applied against the network's block chain; resolving it here
    // keeps the section self-contained (same approach as the anchor section).
    dap_chain_t *l_chain = NULL;
    for (dap_chain_t *l_c = l_net->pub.chains; l_c; l_c = l_c->next) {
        const char *l_cs_type = dap_chain_get_cs_type(l_c);
        if (l_cs_type && !dap_strcmp(l_cs_type, "esbocs")) {
            l_chain = l_c;
            break;
        }
    }
    if (!l_chain && l_net->pub.chains)
        l_chain = l_net->pub.chains;
    if (!l_chain)
        return -4;
    const uint8_t *l_ptr = a_data + sizeof(l_hdr), *l_end = a_data + a_size;
    size_t l_applied = 0, l_kept = 0;
    for (uint64_t i = 0; i < l_hdr.count; ++i) {
        if ((size_t)(l_end - l_ptr) < sizeof(s_decree_journal_rec_t))
            return -5;
        s_decree_journal_rec_t l_rec;
        memcpy(&l_rec, l_ptr, sizeof(l_rec));
        l_ptr += sizeof(l_rec);
        if (!l_rec.size || (size_t)(l_end - l_ptr) < l_rec.size)
            return -5;
        dap_chain_datum_decree_t *l_decree = (dap_chain_datum_decree_t *)l_ptr;
        size_t l_datum_size = dap_chain_datum_decree_get_size(l_decree);
        if (l_datum_size != l_rec.size) {
            log_it(L_WARNING, "Decree journal: record %" DAP_UINT64_FORMAT_U " has inconsistent size %zu != %" DAP_UINT64_FORMAT_U,
                   i, l_datum_size, l_rec.size);
            return -6;
        }
        dap_hash_fast_t l_hash = {};
        dap_hash_fast(l_decree, l_rec.size, &l_hash);
        // Replay through the ordinary path: verification, then apply. Already applied
        // decrees are refused there (-123), which makes the replay idempotent.
        int l_rc = dap_chain_net_decree_load(l_decree, l_chain, &l_hash);
        if (!l_rc || l_rc == -123)
            ++l_applied;
        else
            ++l_kept;   // recorded, not effective (unknown subtype, or already reverted)
        l_ptr += l_rec.size;
    }
    log_it(L_NOTICE, "Decree journal: %zu decree(s) replayed (%zu effective, %zu recorded without effect)",
           (size_t)l_hdr.count, l_applied, l_kept);
    return 0;
}

int dap_chain_net_decree_journal_init(void)
{
    dap_ledger_add_snapshot_section(DAP_NET_DECREE_JOURNAL_SECTION, 0,
            s_decree_journal_dump, s_decree_journal_load, NULL);
    return 0;
}

// Private fuctions prototype
static bool s_verify_pkey (dap_sign_t *a_sign, dap_chain_net_t *a_net);
static int s_common_decree_handler(dap_chain_datum_decree_t *a_decree, dap_chain_net_t *a_net, bool a_apply, bool a_anchored);
static int s_service_decree_handler(dap_chain_datum_decree_t *a_decree, dap_chain_net_t *a_net, bool a_apply);

static bool s_debug_more = false;

// Public functions
int dap_chain_net_decree_init(dap_chain_net_t *a_net)
{
    size_t l_auth_certs_count = 0;

    if (!a_net) {
        log_it(L_WARNING,"Invalid arguments. a_net must be not NULL");
        return -106;
    }

    s_debug_more = dap_config_get_item_bool_default(g_config,"chain_net","debug_more", s_debug_more);

    dap_list_t *l_net_keys = NULL;
    uint16_t l_count_verify = 0;
    for (dap_chain_t *l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next) {
        if (!l_chain->callback_get_poa_certs)
            continue;
        l_net_keys = l_chain->callback_get_poa_certs(l_chain, &l_auth_certs_count, &l_count_verify);
        if (l_net_keys)
            break;
    }

    if (!l_net_keys || !l_auth_certs_count) {
        log_it(L_WARNING,"Certificates for net %s not found.", a_net->pub.name);
        return -1;
    }

    dap_chain_net_decree_t *l_decree = NULL;
    l_decree = DAP_NEW_Z(dap_chain_net_decree_t);
    if (!l_decree) {
        log_it(L_CRITICAL, "Out of memory");
        return -2;
    }

    l_decree->min_num_of_owners = l_count_verify;
    l_decree->num_of_owners = l_auth_certs_count;
    l_decree->pkeys = l_net_keys;
    dap_chain_net_set_net_decree(a_net, l_decree);
    return 0;
}

int dap_chain_net_decree_deinit(dap_chain_net_t *a_net)
{
    dap_return_val_if_fail(a_net, -1);
    dap_chain_policy_net_purge(a_net->pub.id);
    dap_chain_net_decree_t *l_decree = dap_chain_net_get_net_decree(a_net);
    // No decree is a valid state: nets without PoA certificates never get one (decree_init
    // returns early), and a repeated purge must not dereference the freed one.
    if (l_decree) {
        dap_list_free_full(l_decree->pkeys, NULL);
        DAP_DELETE(l_decree);
        dap_chain_net_set_net_decree(a_net, NULL);
    }
    decree_table_t **l_decrees = dap_chain_net_get_decrees(a_net), *l_cur_decree, *l_tmp;
    HASH_ITER(hh, *l_decrees, l_cur_decree, l_tmp) {
        HASH_DEL(*l_decrees, l_cur_decree);
        if ( l_cur_decree->decree && !dap_chain_find_by_id(l_cur_decree->decree->header.common_decree_params.net_id, l_cur_decree->decree->header.common_decree_params.chain_id)->is_mapped )
            DAP_DELETE(l_cur_decree->decree);
        DAP_DELETE(l_cur_decree);
    }
    return 0;
}

void dap_chain_net_decree_purge(dap_chain_net_t *a_net)
{
    dap_chain_net_decree_deinit(a_net);
    dap_chain_net_decree_init(a_net);
}

static int s_decree_verify(dap_chain_net_t *a_net, dap_chain_datum_decree_t *a_decree, size_t a_data_size, dap_chain_hash_fast_t *a_decree_hash, bool a_anchored)
{
    if (a_data_size < sizeof(dap_chain_datum_decree_t)) {
        log_it(L_WARNING, "Decree size is too small");
        return -120;
    }
    if (dap_chain_datum_decree_get_size(a_decree) != a_data_size) {
        log_it(L_WARNING, "Decree size is invalid");
        return -121;
    }
    if (a_decree->header.common_decree_params.net_id.uint64 != a_net->pub.id.uint64) {
        log_it(L_WARNING, "Decree net id is invalid");
        return -122;
    }

    decree_table_t **l_decrees = dap_chain_net_get_decrees(a_net), *l_sought_decree = NULL;
    HASH_FIND(hh, *l_decrees, a_decree_hash, sizeof(dap_hash_fast_t), l_sought_decree);
    if (l_sought_decree && l_sought_decree->decree) {
        debug_if(s_debug_more, L_WARNING, "Decree with hash %s is already present", dap_hash_fast_to_str_static(a_decree_hash));
        return -123;
    }

    // Get pkeys sign from decree datum
    size_t l_signs_size = 0;
    //multiple signs reading from datum
    dap_sign_t *l_signs_block = dap_chain_datum_decree_get_signs(a_decree, &l_signs_size);
    if (!l_signs_size || !l_signs_block)
    {
        log_it(L_WARNING, "Decree data sign not found");
        return -100;
    }

    // Find unique pkeys in pkeys set from previous step and check that number of signs > min
    size_t l_num_of_unique_signs = 0;
    dap_sign_t **l_unique_signs = dap_sign_get_unique_signs(l_signs_block, l_signs_size, &l_num_of_unique_signs);
    dap_chain_net_decree_t *l_net_decree = dap_chain_net_get_net_decree(a_net);
    if (!l_net_decree) {
        log_it(L_ERROR, "Decree module hasn't been initialized yet");
        DAP_DELETE(l_unique_signs);
        return -404;
    }

    uint16_t l_min_signs = l_net_decree->min_num_of_owners;
    if (l_num_of_unique_signs < l_min_signs) {
        log_it(L_WARNING, "Not enough unique signatures, get %zu from %hu", l_num_of_unique_signs, l_min_signs);
        DAP_DELETE(l_unique_signs);
        return -106;
    }

    // Verify all keys and its signatures
    uint16_t l_signs_size_for_current_sign = 0, l_signs_verify_counter = 0;
    dap_chain_datum_decree_t *l_decree = a_net->pub.chains->is_mapped
        ? DAP_DUP_SIZE(a_decree, a_data_size)
        : a_decree;
    l_decree->header.signs_size = 0;
    size_t l_verify_data_size = l_decree->header.data_size + sizeof(dap_chain_datum_decree_t);

    for (size_t i = 0; i < l_num_of_unique_signs; i++) {
        size_t l_sign_max_size = dap_sign_get_size(l_unique_signs[i]);
        if (s_verify_pkey(l_unique_signs[i], a_net)) {
            // 3. verify sign
            if(!dap_sign_verify_all(l_unique_signs[i], l_sign_max_size, l_decree, l_verify_data_size))
                l_signs_verify_counter++;
        } else {
            dap_hash_fast_t l_sign_pkey_hash = {0};
            size_t l_pkey_size = 0;
            uint8_t *l_pkey = dap_sign_get_pkey(l_unique_signs[i], &l_pkey_size);
            log_it(L_WARNING, "Signature [%zu] %s failed public key verification.", i, dap_get_data_hash_str(l_pkey, l_pkey_size).s);
        }
        // Each sign change the sign_size field by adding its size after signing. So we need to change this field in header for each sign.
        l_signs_size_for_current_sign += l_sign_max_size;
        l_decree->header.signs_size = l_signs_size_for_current_sign;
    }

    if ( a_net->pub.chains->is_mapped )
        DAP_DELETE(l_decree);
    else
        l_decree->header.signs_size = l_signs_size;
    DAP_DELETE(l_unique_signs);

    if (l_signs_verify_counter < l_min_signs) {
        log_it(L_WARNING, "Not enough valid signatures, get %hu from %hu", l_signs_verify_counter, l_min_signs);
        return -107;
    }

    // check tsd-section
    int l_ret = 0;
    switch(a_decree->header.type) {
    case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:
        l_ret = s_common_decree_handler(a_decree, a_net, false, a_anchored);
        break;
    case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:
    break;
    default:
        // Unknown decree type: accepted, no effect. See the subtype default in
        // s_common_decree_handler() - the datum is still recorded so that a later
        // build, which knows the type, can apply it without a chain scan.
        log_it(L_NOTICE, "Decree type 0x%04X is not known to this build - accepted without applying",
               a_decree->header.type);
        s_unknown_decree_count++;
    }
    if (l_ret) {
        log_it(L_WARNING, "TSD checking error. Decree verification failed");
        return l_ret;
    }

    return 0;
}

int dap_chain_net_decree_verify(dap_chain_net_t *a_net, dap_chain_datum_decree_t *a_decree, size_t a_data_size, dap_chain_hash_fast_t *a_decree_hash)
{
    return s_decree_verify(a_net, a_decree, a_data_size, a_decree_hash, false);
}

int dap_chain_net_decree_apply(dap_hash_fast_t *a_decree_hash, dap_chain_datum_decree_t *a_decree, dap_chain_t *a_chain, bool a_anchored)
{
    int ret_val = 0;
    dap_chain_net_t *l_net = NULL;

    if (!a_decree_hash || !a_chain)
    {
        log_it(L_ERROR,"Invalid arguments.");
        return -107;
    }

    l_net = dap_chain_net_by_id(a_chain->net_id);
    
    if (!l_net || !dap_chain_net_get_net_decree(l_net))
    {
        log_it(L_WARNING,"Decree is not inited!");
        return -108;
    }

    decree_table_t **l_decrees = dap_chain_net_get_decrees(l_net), *l_new_decree = NULL;
    HASH_FIND(hh, *l_decrees, a_decree_hash, sizeof(dap_hash_fast_t), l_new_decree);
    if (!l_new_decree) {
        l_new_decree = DAP_NEW_Z(decree_table_t);
        if (!l_new_decree) {
            log_it(L_CRITICAL, "Memory allocation error");
            return -1;
        }
        l_new_decree->key = *a_decree_hash;
        HASH_ADD(hh, *l_decrees, key, sizeof(dap_hash_fast_t), l_new_decree);
    }

    if (!a_decree) {    // Processing anchor for decree
        if (!l_new_decree->decree) {
            log_it(L_WARNING, "Decree with hash %s is not found", dap_hash_fast_to_str_static(a_decree_hash));
            l_new_decree->wait_for_apply = true;
            return -110;
        }
        if (l_new_decree->is_applied) {
            debug_if(s_debug_more, L_WARNING, "Decree already applied");
            return -111;
        }
    } else {            // Process decree itself
        if (l_new_decree->decree) {
            debug_if(s_debug_more, L_WARNING, "Decree with hash %s is already present", dap_hash_fast_to_str_static(a_decree_hash));
            return -123;
        }
        l_new_decree->decree = a_chain->is_mapped ? a_decree : DAP_DUP_SIZE(a_decree, dap_chain_datum_decree_get_size(a_decree));
        if (a_decree->header.common_decree_params.chain_id.uint64 != a_chain->id.uint64 && !l_new_decree->wait_for_apply)
            // Apply it with corresponding anchor
            return ret_val;
    }

    // Process decree
    switch(l_new_decree->decree->header.type) {
    case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:
        ret_val = s_common_decree_handler(l_new_decree->decree, l_net, true, a_anchored);
        break;
    case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:
        break;
    default:
        // Unknown decree type: accepted, no effect (see s_common_decree_handler())
        log_it(L_NOTICE, "Decree type 0x%04X is not known to this build - accepted without applying",
               l_new_decree->decree->header.type);
        s_unknown_decree_count++;
    }

    if (!ret_val) {
        l_new_decree->is_applied = true;
        l_new_decree->wait_for_apply = false;
    } else
        debug_if(s_debug_more, L_ERROR,"Decree applying failed!");

    return ret_val;
}

int dap_chain_net_decree_load(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain, dap_chain_hash_fast_t *a_decree_hash)
{
    int ret_val = 0;
    if (!a_chain || !a_decree) {
        log_it(L_ERROR, "Bad arguments");
        return -100;
    }

    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);

    if ( !dap_chain_net_get_net_decree(l_net) ) {
        log_it(L_WARNING, "Decree is not inited!");
        return -108;
    }

    size_t l_data_size = dap_chain_datum_decree_get_size(a_decree);

    if ((ret_val = s_decree_verify(l_net, a_decree, l_data_size, a_decree_hash, false)) != 0) {
        //log_it(L_ERROR, "Decree verification failed!");
        return ret_val;
    }

    return dap_chain_net_decree_apply(a_decree_hash, a_decree, a_chain, false);
}

int dap_chain_net_decree_reset_applied(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_decree_hash)
{
    if (!a_net || !a_decree_hash)
        return -1;
    decree_table_t **l_decrees = dap_chain_net_get_decrees(a_net), *l_sought_decree = NULL;
    HASH_FIND(hh, *l_decrees, a_decree_hash, sizeof(dap_hash_fast_t), l_sought_decree);
    if (!l_sought_decree)
        return -2;
    l_sought_decree->is_applied = false;
    return 0;
}

dap_chain_datum_decree_t *dap_chain_net_decree_get_by_hash(dap_chain_net_t *a_net, dap_hash_fast_t *a_hash, bool *is_applied)
{
    decree_table_t **l_decrees = dap_chain_net_get_decrees(a_net), *l_sought_decree = NULL;
    HASH_FIND(hh, *l_decrees, a_hash, sizeof(dap_hash_fast_t), l_sought_decree);
    return ( !l_sought_decree || !l_sought_decree->decree )
        ? NULL
        : ({ if (is_applied) { *is_applied = l_sought_decree->is_applied; } l_sought_decree->decree; });
}

// Private functions
static bool s_verify_pkey (dap_sign_t *a_sign, dap_chain_net_t *a_net)
{
    for (dap_list_t *it = dap_chain_net_get_net_decree(a_net)->pkeys; it; it = it->next)
        if (dap_pkey_compare_with_sign(it->data, a_sign))
            return true;
    return false;
}

static int s_common_decree_handler(dap_chain_datum_decree_t *a_decree, dap_chain_net_t *a_net, bool a_apply, bool a_anchored)
{
    uint256_t l_value;
    uint32_t l_sign_type;
    uint16_t l_owners_num;
    uint8_t l_action;
    dap_chain_addr_t l_addr = {};
    dap_hash_fast_t l_hash = {};
    dap_chain_node_addr_t l_node_addr = {};
    dap_list_t *l_owners_list = NULL;
    const char *l_ban_addr;

    dap_return_val_if_fail(a_decree && a_net, -112);

    switch (a_decree->header.sub_type)
    {
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE:
                // if (dap_chain_datum_decree_get_fee_addr(a_decree, &l_addr)) {
                //     if (dap_chain_addr_is_blank(&a_net->pub.fee_addr)) {
                //         log_it(L_WARNING, "Fee wallet address not set.");
                //         return -111;
                //     } else
                //         l_addr = a_net->pub.fee_addr;
                // }
                if (dap_chain_datum_decree_get_fee(a_decree, &l_value)) {
                    log_it(L_WARNING,"Can't get fee value from decree.");
                    return -103;
                }
                if (!a_anchored)
                    break;
                if (dap_chain_datum_decree_get_fee_addr(a_decree, &l_addr)) {
                    if (dap_chain_addr_is_blank(&a_net->pub.fee_addr)) {
                        log_it(L_WARNING, "Fee wallet address not set.");
                        return -111;
                    } else
                        l_addr = a_net->pub.fee_addr;
                }
                if (!a_apply)
                    break;
                if (!dap_chain_net_tx_set_fee(a_net->pub.id, l_value, l_addr))
                    log_it(L_ERROR, "Can't set fee value for network %s", a_net->pub.name);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS:
            l_owners_list = dap_chain_datum_decree_get_owners(a_decree, &l_owners_num);
            if (!l_owners_list){
                log_it(L_WARNING,"Can't get ownners from decree.");
                return -104;
            }
            if (!a_apply)
                break;
            dap_chain_net_decree_t *l_net_decree = dap_chain_net_get_net_decree(a_net);
            l_net_decree->num_of_owners = l_owners_num;
            dap_list_free_full(l_net_decree->pkeys, NULL);

            l_net_decree->pkeys = l_owners_list;
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN:
            if (dap_chain_datum_decree_get_min_owners(a_decree, &l_value)) {
                log_it(L_WARNING, "Can't get min number of ownners from decree.");
                return -105;
            }
            if (IS_ZERO_256(l_value) || compare256(l_value, GET_256_FROM_64(UINT16_MAX)) == 1) {
                log_it(L_WARNING, "Illegal min number of owners %s", dap_uint256_to_char(l_value, NULL));
                return -116;
            }
            if (!a_apply)
                break;
            dap_chain_net_get_net_decree(a_net)->min_num_of_owners = dap_uint256_to_uint64(l_value);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE:
            if (dap_chain_datum_decree_get_hash(a_decree, &l_hash)){
                log_it(L_WARNING,"Can't get tx hash from decree.");
                return -105;
            }
            if (dap_chain_datum_decree_get_stake_value(a_decree, &l_value)){
                log_it(L_WARNING,"Can't get stake value from decree.");
                return -106;
            }
            if (dap_chain_datum_decree_get_stake_signing_addr(a_decree, &l_addr)){
                log_it(L_WARNING,"Can't get signing address from decree.");
                return -107;
            }
            if (dap_chain_datum_decree_get_stake_signer_node_addr(a_decree, &l_node_addr)){
                log_it(L_WARNING,"Can't get signer node address from decree.");
                return -108;
            }
            if (!a_anchored)
                break;
            if (dap_chain_net_srv_stake_verify_key_and_node(&l_addr, &l_node_addr)) {
                debug_if(s_debug_more, L_WARNING, "Key and node verification error");
                return -109;
            }
            if (!a_apply)
                break;
            
            dap_chain_net_srv_stake_key_delegate(a_net, &l_addr, &l_hash, l_value, &l_node_addr, dap_chain_datum_decree_get_pkey(a_decree));
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_PKEY_UPDATE:
            if (!a_anchored)
                break;
            if (!a_apply)
                break;
            dap_pkey_t *l_pkey = NULL;
            if (! (l_pkey = dap_chain_datum_decree_get_pkey(a_decree)) ){
                log_it(L_WARNING,"Can't get pkey from decree.");
                return -105;
            }
            dap_chain_net_srv_stake_pkey_update(a_net, l_pkey);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE: {
            if (dap_chain_datum_decree_get_stake_signing_addr(a_decree, &l_addr)){
                log_it(L_WARNING,"Can't get signing address from decree.");
                return -105;
            }
            if (!a_anchored)
                break;
            uint16_t l_min_count = dap_chain_esbocs_get_min_validators_count(a_net->pub.id);
            if ( dap_chain_net_srv_stake_get_total_keys(a_net->pub.id, NULL) == l_min_count ) {
                log_it(L_WARNING, "Can't invalidate stake in net %s: results in minimum validators count %hu underflow",
                                   a_net->pub.name, l_min_count);
                return -116;
            }
            if (!a_apply)
                break;
            dap_chain_net_srv_stake_key_invalidate(&l_addr);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE:
            if (dap_chain_datum_decree_get_stake_min_value(a_decree, &l_value)){
                log_it(L_WARNING,"Can't get min stake value from decree.");
                return -105;
            }
            if (!a_apply)
                break;
            dap_chain_net_srv_stake_set_allowed_min_value(a_net->pub.id, l_value);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT: {
            if (dap_chain_datum_decree_get_stake_min_signers_count(a_decree, &l_value)){
                log_it(L_WARNING,"Can't get min stake value from decree.");
                return -105;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!a_anchored)
                break;
            uint16_t l_decree_count = (uint16_t)dap_chain_uint256_to(l_value);
            uint16_t l_current_count = dap_chain_net_srv_stake_get_total_keys(a_net->pub.id, NULL);
            if (l_decree_count > l_current_count) {
                log_it(L_WARNING, "Minimum validators count by decree %hu is greater than total validators count %hu in network %s",
                                                                            l_decree_count, l_current_count, a_net->pub.name);
                return -116;
            }
            if (!a_apply)
                break;
            dap_chain_esbocs_set_min_validators_count(l_chain, l_decree_count);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_BAN: {
            if (dap_chain_datum_decree_get_ban_addr(a_decree, &l_ban_addr)) {
                log_it(L_WARNING, "Can't get ban address from decree.");
                return -114;
            }
            if (dap_http_ban_list_client_check(l_ban_addr, NULL, NULL)) {
                log_it(L_ERROR, "Can't ban addr %s: already banlisted", l_ban_addr);
                return -112;
            }
            if (!a_apply)
                break;
            dap_hash_fast_t l_decree_hash = {0};
            dap_hash_fast(a_decree, dap_chain_datum_decree_get_size(a_decree), &l_decree_hash);
            dap_http_ban_list_client_add(l_ban_addr, l_decree_hash, a_decree->header.ts_created);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_UNBAN: {
            if (dap_chain_datum_decree_get_ban_addr(a_decree, &l_ban_addr)) {
                log_it(L_WARNING, "Can't get ban address from decree.");
                return -114;
            }
            if (!dap_http_ban_list_client_check(l_ban_addr, NULL, NULL)) {
                log_it(L_ERROR, "Can't ban addr %s: already banlisted", l_ban_addr);
                return -112;
            }
            if (!a_apply)
                break;
            dap_http_ban_list_client_remove(l_ban_addr);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_REWARD: {
            if (dap_chain_datum_decree_get_value(a_decree, &l_value)) {
                log_it(L_WARNING,"Can't get value from decree.");
                return -103;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!a_apply)
                break;
            uint64_t l_cur_block_num = l_chain->callback_count_atom(l_chain);
            dap_chain_net_add_reward(a_net, l_value, l_cur_block_num);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_MAX_WEIGHT: {
            if (dap_chain_datum_decree_get_value(a_decree, &l_value)) {
                log_it(L_WARNING,"Can't get value from decree.");
                return -103;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (compare256(l_value, dap_chain_coins_to_balance("1.0")) >= 0) {
                log_it(L_WARNING, "Percent must be lower than 100%%");
                return -116;
            }
            if (!a_apply)
                break;
            dap_chain_net_srv_stake_set_percent_max(a_net->pub.id, l_value);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_CHECK_SIGNS_STRUCTURE: {
            if (dap_chain_datum_decree_get_action(a_decree, &l_action)) {
                log_it(L_WARNING,"Can't get action from decree.");
                return -103;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!a_apply)
                break;
            dap_chain_esbocs_set_signs_struct_check(l_chain, l_action);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_CONSENSUS_VERSION: {
            uint64_t l_version = 0;
            dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size,
                                            DAP_CHAIN_DATUM_DECREE_TSD_TYPE_CONSENSUS_VERSION);
            if (!l_tsd || l_tsd->size != sizeof(uint64_t)) {
                log_it(L_WARNING, "Can't get consensus version from decree.");
                return -103;
            }
            _dap_tsd_get_scalar(l_tsd, &l_version);
            if (l_version < 2) {
                // Version 1 is the pre-decree era itself; a decree cannot downgrade below 2
                log_it(L_WARNING, "Consensus version decree must be >= 2, got %"DAP_UINT64_FORMAT_U, l_version);
                return -103;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!a_apply)
                break;
            dap_chain_esbocs_set_consensus_version(l_chain, l_version, (uint64_t)a_decree->header.ts_created);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMERGENCY_VALIDATORS: {
            if (dap_chain_datum_decree_get_action(a_decree, &l_action)) {
                log_it(L_WARNING,"Can't get action from decree.");
                return -103;
            }
            if (dap_chain_datum_decree_get_signature_type(a_decree, &l_sign_type)) {
                log_it(L_WARNING,"Can't get signature type from decree.");
                return -113;
            }
            if (dap_chain_datum_decree_get_hash(a_decree, &l_hash)){
                log_it(L_WARNING,"Can't get validator hash from decree.");
                return -105;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!a_apply)
                break;
            dap_chain_esbocs_set_emergency_validator(l_chain, l_action, l_sign_type, &l_hash);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_POLICY: {
            if (!a_apply)
                break;
            dap_chain_policy_t *l_policy = NULL;
            if ( !(l_policy = dap_chain_datum_decree_get_policy(a_decree)) ){
                log_it(L_WARNING,"Can't get policy from decree.");
                return -105;
            }
            return dap_chain_policy_apply(l_policy, a_net->pub.id);
        }
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMPTY_BLOCKGEN: {
            if (!a_apply)
                break;
            if (!a_anchored)
                break;
            uint16_t l_blockgen_period = 0;
            if (dap_chain_datum_decree_get_empty_block_every_times(a_decree, &l_blockgen_period)){
                log_it(L_WARNING,"Can't get empty blockgen period from decree.");
                return -105;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            return dap_chain_esbocs_set_empty_block_every_times(l_chain, l_blockgen_period);
        }
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EVENT_PKEY_ADD: {
            dap_hash_fast_t l_pkey_hash;
            if (dap_chain_datum_decree_get_hash(a_decree, &l_pkey_hash)) {
                log_it(L_WARNING, "Can't get event pkey hash from decree.");
                return -114;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (!a_anchored)
                break;
            if (!dap_ledger_event_pkey_check(a_net->pub.ledger, &l_pkey_hash)) {
                log_it(L_WARNING, "Event pkey already exists in ledger");
                return -116;
            }
            if (!a_apply)
                break;
            int l_ret = dap_ledger_event_pkey_add(a_net->pub.ledger, &l_pkey_hash);
            if (l_ret != 0) {
                log_it(L_INFO, "Error adding event pkey to ledger: %d", l_ret);
                return -118;
            }
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EVENT_PKEY_REMOVE: {
            dap_hash_fast_t l_pkey_hash;
            if (dap_chain_datum_decree_get_hash(a_decree, &l_pkey_hash)) {
                log_it(L_WARNING, "Can't get event pkey hash from decree.");
                return -114;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (!a_anchored)
                break;
            if (dap_ledger_event_pkey_check(a_net->pub.ledger, &l_pkey_hash)) {
                log_it(L_WARNING, "Event pkey not found in ledger");
                return -116;
            }
            if (!a_apply)
                break;
            int l_ret = dap_ledger_event_pkey_rm(a_net->pub.ledger, &l_pkey_hash);
            if (l_ret != 0) {
                log_it(L_ERROR, "Error removing event pkey from ledger: %d", l_ret);
                return -118;
            }
        } break;
        default:
            // A decree subtype this binary does not know yet. Accept it so the datum
            // reaches the decree table (and, through it, the snapshot journal) instead
            // of being rejected: after a software upgrade the same decree must be able
            // to become effective without a full chain scan. Nothing is applied here -
            // an unrecognized subtype has no effect by definition. Rejecting it, as was
            // done before, silently discarded both the decree and the state it carries
            // for every node running an older build.
            log_it(L_NOTICE, "Decree subtype 0x%04X is not known to this build - accepted without applying (net %s)",
                   a_decree->header.sub_type, a_net->pub.name);
            s_unknown_decree_count++;
            break;
    }

    return 0;
}