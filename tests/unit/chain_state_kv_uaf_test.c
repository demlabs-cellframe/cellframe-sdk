/*
 * Regression: deleting a chain-state key and then writing that same key again
 * must not touch freed memory.
 *
 * The cache keeps two uthash tables over one entry (by numeric id and by name),
 * and HASH_DELETE_HH-style deletion has to unlink EACH of them through its OWN
 * handle. dap_chain_state_kv_del() used HASH_DEL(head, el) twice -
 *
 *     HASH_DEL(a_kv->by_id, l_e);
 *     HASH_DEL(a_kv->by_name, l_e);
 *
 * - and HASH_DEL always expands to HASH_DELETE_HH(hh, head, &el->hh), i.e. it
 * unlinks the hh handle from the head it is given, whatever that head is. Both
 * calls therefore deleted the SAME element from by_id, and by_name kept a
 * pointer to the entry after DAP_DELETE(l_e) freed it. When that element was the
 * last one in by_id, the second HASH_DELETE_HH freed the by_id TABLE and NULLed
 * the head it was handed - which was by_name's head.
 *
 * The next write of the same key then resolved the name to that dangling entry
 * and wrote into it: use-after-free on a freed heap block (valgrind: "Invalid
 * write of size 8 ... inside a block free'd"), and the corrupted heap surfaced
 * far away, as a crash inside malloc from unrelated code. Live symptom: the DEX
 * integration test (which deletes and rewrites its history journal in the same
 * run) segfaulted in ~1 s, and the same sequence on a node corrupts the heap of
 * the process owning the registry.
 *
 * The test drives the public facade - set, delete, set again - and then reads the
 * value back. Without the fix the second set writes into freed memory: the read
 * returns nothing (or garbage) and valgrind reports the invalid write.
 *
 * The group name is local to this test so the assertions cannot be satisfied by
 * entries another part of the process left behind.
 */

#include "dap_common.h"
#include "dap_test.h"
#include "dap_chain_state_cache.h"

#define LOG_TAG "chain_state_kv_uaf_test"

static const char *s_group = "local.chain_state_kv_uaf_test";

static void test_rewrite_after_delete(void)
{
    const char *l_key = "journal_entry_17";
    const char *l_first = "https://example.invalid/journal.png";
    const char *l_second = "https://example.invalid/journal-v2.png";

    // Fresh entry: this is the allocation whose free the buggy delete leaks into
    // the by-name table.
    dap_assert(dap_chain_state_cache_set(s_group, l_key, l_first, strlen(l_first) + 1) == 0,
               "first write of a new key succeeds");

    size_t l_len = 0;
    const char *l_got = (const char *)dap_chain_state_cache_get(s_group, l_key, &l_len);
    dap_assert(l_got && l_len == strlen(l_first) + 1 && !strcmp(l_got, l_first),
               "value reads back before the delete");

    // Delete it, then write the SAME key again. With the two-handle bug the
    // second set resolves the name to the freed entry.
    dap_assert(dap_chain_state_cache_del(s_group, l_key) == 0, "delete succeeds");
    dap_assert(dap_chain_state_cache_get(s_group, l_key, &l_len) == NULL,
               "a deleted key reads back as absent");

    dap_assert(dap_chain_state_cache_set(s_group, l_key, l_second, strlen(l_second) + 1) == 0,
               "rewriting the same key after its delete succeeds");

    l_got = (const char *)dap_chain_state_cache_get(s_group, l_key, &l_len);
    dap_assert(l_got && l_len == strlen(l_second) + 1 && !strcmp(l_got, l_second),
               "the rewritten key returns the new value, not memory the delete freed");
}

static void test_delete_every_key_then_rewrite(void)
{
    // Same shape with several keys, so the deleted entry is not the only one and
    // the by-id table survives the delete (the case that additionally orphaned
    // the by-name head).
    const int l_keys = 5;
    char l_key[32];
    char l_value[64];

    for (int i = 0; i < l_keys; ++i) {
        snprintf(l_key, sizeof(l_key), "multi_%d", i);
        snprintf(l_value, sizeof(l_value), "value-%d", i);
        dap_assert(dap_chain_state_cache_set(s_group, l_key, l_value, strlen(l_value) + 1) == 0,
                   "multi-key write succeeds");
    }
    for (int i = 0; i < l_keys; ++i) {
        snprintf(l_key, sizeof(l_key), "multi_%d", i);
        dap_assert(dap_chain_state_cache_del(s_group, l_key) == 0, "multi-key delete succeeds");
    }
    for (int i = 0; i < l_keys; ++i) {
        snprintf(l_key, sizeof(l_key), "multi_%d", i);
        snprintf(l_value, sizeof(l_value), "rewritten-%d", i);
        dap_assert(dap_chain_state_cache_set(s_group, l_key, l_value, strlen(l_value) + 1) == 0,
                   "multi-key rewrite after delete succeeds");

        size_t l_len = 0;
        const char *l_got = (const char *)dap_chain_state_cache_get(s_group, l_key, &l_len);
        dap_assert(l_got && !strcmp(l_got, l_value),
                   "multi-key rewritten value reads back intact");
    }

    // Every rewritten key must still be readable, and deleting a key must not
    // leave a second entry for its name behind: reading by name resolves to one
    // entry, so a name table still holding freed entries would show up as a
    // lookup that finds a stale record (it used to re-mint ids instead).
    for (int i = 0; i < l_keys; ++i) {
        snprintf(l_key, sizeof(l_key), "multi_%d", i);
        snprintf(l_value, sizeof(l_value), "final-%d", i);
        dap_assert(dap_chain_state_cache_set(s_group, l_key, l_value, strlen(l_value) + 1) == 0,
                   "final rewrite of every key succeeds");
    }
    for (int i = 0; i < l_keys; ++i) {
        snprintf(l_key, sizeof(l_key), "multi_%d", i);
        snprintf(l_value, sizeof(l_value), "final-%d", i);

        size_t l_len = 0;
        const char *l_got = (const char *)dap_chain_state_cache_get(s_group, l_key, &l_len);
        dap_assert(l_got && l_len == strlen(l_value) + 1 && !strcmp(l_got, l_value),
                   "every key resolves to its own final value (no stale entry shadowing it)");
    }
}

int main(int argc, char **argv)
{
    dap_common_init(LOG_TAG, NULL);
    UNUSED(argc); UNUSED(argv);

    dap_print_module_name("chain_state_kv_uaf");
    test_rewrite_after_delete();
    test_delete_every_key_then_rewrite();

    dap_assert(1, "chain-state KV delete-then-rewrite tests passed");
    dap_common_deinit();
    return 0;
}