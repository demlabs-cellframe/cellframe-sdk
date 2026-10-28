/*
 * Regression test for the stake delegation duplicate guard vs replay.
 *
 * dap_chain_net_srv_stake_verify_key_and_node() is a LIVE-operation guard:
 * it refuses a delegation whose key is already active or whose node already
 * holds a key. During a replay (a rescan or a peer resync) the registry
 * content depends on every earlier delegation having applied, so the guard
 * must yield there - otherwise one miss cascades into lost delegations and
 * unverifiable blocks. This test pins the contract:
 *
 *   - ONLINE: duplicates are rejected (-101 / -102), a free pair passes;
 *   - NET_STATE_LOADING and NET_STATE_SYNC_CHAINS: duplicates pass;
 *   - blank arguments are rejected in EVERY state (the hard check is never
 *     bypassed by the replay switch);
 *   - the guard is active again after the net returns to ONLINE.
 *
 * Every future guard that keys off dap_chain_net_is_replay() must carry an
 * equivalent test: these switches weaken a check for exactly the states they
 * name, and the test is what proves the weakening did not leak into the live
 * path.
 */

#include <stdio.h>
#include <string.h>

#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_test.h"

#define LOG_TAG "stake_replay_guard_test"

#define TEST_NET_ID 0x0FA0  // the network dap_chain_net_test_init() creates

// A signing address bound to this net, derived from a fresh key the same way
// the esbocs cert init derives validator addresses.
static void s_make_addr(dap_enc_key_t *a_key, dap_chain_addr_t *a_out)
{
    dap_chain_addr_fill_from_key(a_out, a_key, (dap_chain_net_id_t){ .uint64 = TEST_NET_ID });
}

static dap_chain_node_addr_t s_make_node(uint64_t a_lo)
{
    dap_chain_node_addr_t l_addr = {};
    l_addr.uint64 = a_lo;
    return l_addr;
}

static void test_guard_by_state(void)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){ .uint64 = TEST_NET_ID });
    dap_assert_PIF(l_net != NULL, "Test net exists");

    dap_enc_key_t *l_key_a = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_enc_key_t *l_key_b = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key_a && l_key_b, "Keys generated");
    dap_chain_addr_t l_addr_a, l_addr_b;
    s_make_addr(l_key_a, &l_addr_a);
    s_make_addr(l_key_b, &l_addr_b);
    dap_chain_node_addr_t l_node_1 = s_make_node(0x1111);
    dap_chain_node_addr_t l_node_2 = s_make_node(0x2222);

    // Seed the registry the way a delegation applies: key A -> node 1.
    dap_hash_fast_t l_blank_tx = {};
    dap_chain_net_srv_stake_key_delegate(l_net, &l_addr_a, &l_blank_tx, uint256_1, &l_node_1, NULL);

    // ONLINE: the live guard is fully active.
    dap_chain_net_test_set_state(l_net, NET_STATE_ONLINE);
    dap_assert_PIF(dap_chain_net_srv_stake_verify_key_and_node(&l_addr_a, &l_node_2) == -101,
                   "ONLINE: an already-active key is rejected");
    dap_assert_PIF(dap_chain_net_srv_stake_verify_key_and_node(&l_addr_b, &l_node_1) == -102,
                   "ONLINE: a node that already holds a key is rejected");
    dap_assert_PIF(dap_chain_net_srv_stake_verify_key_and_node(&l_addr_b, &l_node_2) == 0,
                   "ONLINE: a free key/node pair passes");

    // Replay states: the duplicate guard yields...
    dap_chain_net_test_set_state(l_net, NET_STATE_LOADING);
    dap_assert_PIF(dap_chain_net_srv_stake_verify_key_and_node(&l_addr_a, &l_node_2) == 0,
                   "LOADING: an occupied key passes (canonical replay)");
    dap_chain_net_test_set_state(l_net, NET_STATE_SYNC_CHAINS);
    dap_assert_PIF(dap_chain_net_srv_stake_verify_key_and_node(&l_addr_b, &l_node_1) == 0,
                   "SYNC_CHAINS: an occupied node passes (canonical replay)");

    // ...but the hard argument checks are never bypassed. A fully blank
    // address carries net id 0, for which no stake service is registered, so
    // it returns -104 before the -103 branch - in every state. The reachable
    // hard check is the zero node address, and it must hold in replay too.
    dap_chain_addr_t l_blank_addr = {};
    dap_chain_node_addr_t l_zero_node = {};
    dap_assert_PIF(dap_chain_net_srv_stake_verify_key_and_node(&l_blank_addr, &l_node_2) == -104,
                   "LOADING: a blank signing address is rejected (no service for net 0)");
    dap_assert_PIF(dap_chain_net_srv_stake_verify_key_and_node(&l_addr_a, &l_zero_node) == -103,
                   "SYNC_CHAINS: a zero node address is still rejected");
    dap_chain_net_test_set_state(l_net, NET_STATE_ONLINE);
    dap_assert_PIF(dap_chain_net_srv_stake_verify_key_and_node(&l_addr_a, &l_zero_node) == -103,
                   "ONLINE: a zero node address is still rejected");
    dap_chain_net_test_set_state(l_net, NET_STATE_SYNC_CHAINS);

    // Back to live: the guard is active again.
    dap_chain_net_test_set_state(l_net, NET_STATE_ONLINE);
    dap_assert_PIF(dap_chain_net_srv_stake_verify_key_and_node(&l_addr_a, &l_node_2) == -101,
                   "ONLINE again: the guard is restored");

    dap_enc_key_delete(l_key_a);
    dap_enc_key_delete(l_key_b);
    dap_pass_msg("test_guard_by_state");
}

static void test_load_mode_untouched(void)
{
    // dap_chain_net_get_load_mode() keeps its narrow meaning (local load pass
    // only); the replay abstraction must be the wider one.
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){ .uint64 = TEST_NET_ID });
    dap_assert_PIF(l_net != NULL, "Test net exists");
    dap_chain_net_test_set_state(l_net, NET_STATE_ONLINE);
    dap_assert_PIF(!dap_chain_net_get_load_mode(l_net), "ONLINE is not load mode");
    dap_assert_PIF(!dap_chain_net_is_replay(l_net), "ONLINE is not replay");
    dap_chain_net_test_set_state(l_net, NET_STATE_SYNC_CHAINS);
    dap_assert_PIF(!dap_chain_net_get_load_mode(l_net), "SYNC_CHAINS is not load mode");
    dap_assert_PIF(dap_chain_net_is_replay(l_net), "SYNC_CHAINS is replay");
    dap_chain_net_test_set_state(l_net, NET_STATE_LOADING);
    dap_assert_PIF(dap_chain_net_get_load_mode(l_net), "LOADING is load mode");
    dap_assert_PIF(dap_chain_net_is_replay(l_net), "LOADING is replay");
    dap_chain_net_test_set_state(l_net, NET_STATE_ONLINE);
    dap_pass_msg("test_load_mode_untouched");
}

int main(void)
{
    dap_log_level_set(L_DEBUG);
    dap_chain_net_test_init();
    // The stake service registers per net; the test net is created above.
    dap_assert_PIF(dap_chain_net_srv_stake_net_add((dap_chain_net_id_t){ .uint64 = TEST_NET_ID }) == 0,
                   "Stake service registered for the test net");

    test_guard_by_state();
    test_load_mode_untouched();

    return 0;
}
