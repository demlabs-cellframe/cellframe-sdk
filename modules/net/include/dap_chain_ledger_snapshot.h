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
 * @brief Disarm the chain-scan skip (the loader reached the snapshot position
 *        and switched to full processing, or the snapshot is from another branch).
 */
void dap_ledger_snapshot_skip_consume(dap_ledger_t *a_ledger);


#ifdef __cplusplus
}
#endif
