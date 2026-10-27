/*
 * dap_chain_ledger_snapshot.h
 *
 * Ledger snapshot cache: a flat binary file in the chain data directory that
 * captures the in-memory ledger state (per-transaction cache records with
 * their spent-outs bookkeeping, and every account balance) together with the
 * chain position it is consistent with.
 *
 * Unlike the GlobalDB ledger cache (local.ledger-cache.<net>.* groups) the
 * snapshot does not go through the GlobalDB layer at all: no groups, no
 * replication, no per-record signing, no size-limit interaction with the
 * node's other GlobalDB data - a full Backbone replay cannot push the node's
 * GlobalDB over its hard limit through ledger cache writes anymore.
 *
 * A snapshot is written periodically (and can be requested manually); on load
 * the file is restored into the ledger before the chain scan starts, and the
 * scan itself completes every restored transaction cache item with the datum
 * seen in the chain (see dap_ledger_tx_load). An unusable snapshot simply
 * falls back to the regular load path - the file is always just an index.
 */
#pragma once

#include "dap_chain_ledger.h"
#include "dap_string.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Whether the snapshot mode is active for this ledger
 *        ([ledger] snapshot_cache, requires cache_enabled).
 */
bool dap_ledger_snapshot_mode(dap_ledger_t *a_ledger);

/**
 * @brief Restore the ledger state from the snapshot file.
 * @return 1 - snapshot loaded; 0 - no usable snapshot (fall back); <0 - error.
 */
int dap_ledger_snapshot_load(dap_ledger_t *a_ledger);

/**
 * @brief Write the current ledger state to the snapshot file (atomically:
 *        temporary file + rename).
 * @param a_shutdown true when called on the shutdown path (logging wording only).
 * @return 0 on success.
 */
int dap_ledger_snapshot_save(dap_ledger_t *a_ledger, bool a_shutdown);

/**
 * @brief Chain-scan skip anchor (armed when a snapshot with a chain tip is
 *        restored): the cs-blocks loader consumes it to skip RE-VERIFICATION of
 *        the blocks the snapshot already covers - their datums still flow into
 *        the ledger - up to the continuity check at the snapshot position. Only
 *        used in builds with DAP_LEDGER_SNAPSHOT_SKIP_EXPERIMENTAL; compiling
 *        the API unconditionally keeps the loader's call sites
 *        declaration-complete.
 * @return true when a skip is armed; false otherwise (caller does the full work).
 */
bool dap_ledger_snapshot_skip_get(dap_ledger_t *a_ledger, uint64_t *a_block_num, dap_chain_hash_fast_t *a_block_hash);

/**
 * @brief Arm the chain-scan skip from another trusted local source (the chain
 *        state sidecar). No-op when an anchor is already armed: the ledger
 *        snapshot is authoritative and knows its own tip.
 */
void dap_ledger_snapshot_skip_set(dap_ledger_t *a_ledger, uint64_t a_block_num,
                                  const dap_chain_hash_fast_t *a_block_hash);

/**
 * @brief Snapshot section registry (v3).
 *
 * Services register a named section; the ledger core knows nothing about their
 * data. On save the dump callback fills a string buffer; on load the section is
 * handed back verbatim (a_size == what was dumped). Unknown sections in a file
 * are skipped by size, so a newer snapshot still loads on an older node.
 * Registration is idempotent by name (the first registration wins).
 */
#define DAP_LEDGER_SNAPSHOT_SECTION_NAME_MAX 32
// A section registered with this flag makes the snapshot a COMPLETE ledger
// state: header flag bit2 is set and, when [ledger] snapshot_full_apply is on,
// the ledger stops replaying the service side of the restored transactions
// (polls/votes, events, rewards, conditional-service notifications) because the
// sections carry that state. Only the ledger's own "ledger_state" section does.
#define DAP_LEDGER_SNAPSHOT_SECTION_FLAG_FULL 0x1u
// Apply the section right after the snapshot is read, BEFORE the chain scan,
// instead of at load end. For state the loader itself needs during the scan
// (e.g. how much of a DAG index the snapshot already covers).
#define DAP_LEDGER_SNAPSHOT_SECTION_FLAG_EARLY 0x2u
#define DAP_LEDGER_SNAPSHOT_LEDGER_STATE_SECTION "ledger_state"
// The dump callback receives the network whose snapshot is being written, so a
// section must only emit that network's state (several networks share the
// process and each has its own snapshot file).
typedef int (*dap_ledger_snapshot_dump_cb_t)(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out);
typedef int (*dap_ledger_snapshot_load_cb_t)(void *a_ctx, const uint8_t *a_data, size_t a_size);

int dap_ledger_add_snapshot_section(const char *a_name, uint32_t a_flags,
        dap_ledger_snapshot_dump_cb_t a_dump, dap_ledger_snapshot_load_cb_t a_load, void *a_ctx);

// Services register their persistent GlobalDB group(s) here instead of relying on
// the GDB contents surviving/being complete: the "service_groups" section dumps
// every registered group per network and restores missing records synchronously
// at load. The getter returns a malloc'd group name for the net (or NULL).
typedef char *(*dap_ledger_snapshot_group_getter_t)(dap_chain_net_t *a_net, void *a_ctx);
int dap_ledger_add_snapshot_gdb_group(const char *a_name, dap_ledger_snapshot_group_getter_t a_getter, void *a_ctx);

/**
 * @brief Whether the loaded snapshot was a COMPLETE ledger state (the
 *        "ledger_state" section restored successfully, header flag bit2).
 */
bool dap_ledger_snapshot_is_full(dap_ledger_t *a_ledger);

/**
 * @brief Whether the restored transactions' service replay is suppressed
 *        ([ledger] snapshot_full_apply and a complete snapshot was loaded).
 */
bool dap_ledger_snapshot_full_apply_enabled(dap_ledger_t *a_ledger);

/**
 * @brief Disarm the chain-scan skip (the loader reached the snapshot position
 *        and switched to full processing, or the snapshot is from another branch).
 */
void dap_ledger_snapshot_skip_consume(dap_ledger_t *a_ledger);

/**
 * @brief Record that a datum of block @a a_block_num did not apply to the
 *        ledger. Keeps the lowest such block; the snapshot save anchors before
 *        it so the file never claims coverage it does not carry.
 */
void dap_ledger_replay_datum_failed(dap_ledger_t *a_ledger, uint64_t a_block_num);

/**
 * @brief Clear the anchor holdback (after a purge or a full ledger rebuild).
 */
void dap_ledger_replay_fail_reset(dap_ledger_t *a_ledger);


#ifdef __cplusplus
}
#endif
