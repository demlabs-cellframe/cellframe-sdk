/*
 * Chain state layer: the persistent, chain-wide state that is not specific to
 * one consensus/type module. Today it carries the linear block index sidecar
 * ("<cell file>.state") used to validate and, in the next step, rebuild the
 * block cache without re-reading cell files; the same object is the intended
 * anchor for future EVM/WASM smart-contract state adapters (block/datum/tx
 * indexes, accounts/storage roots).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "dap_chain.h"
#include "dap_chain_common.h"
#include "dap_hash.h"
#include "dap_string.h"
#include "uthash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DAP_CHAIN_STATE_VERSION 5
// crc64() = crc64_update(init, ...) ^ xorout with init = xorout = ~0; keeping the
// running value lets the records CRC stay incremental.
#define DAP_CHAIN_STATE_CRC_INIT UINT64_C(~0)
#define DAP_CHAIN_STATE_CRC_XOROUT UINT64_C(~0)

typedef struct dap_chain_state dap_chain_state_t;

// Datum hash -> block link (the chain-wide datum index). block_ref is the
// consensus layer's block object, opaque here.
typedef struct dap_chain_state_datum {
    dap_chain_hash_fast_t datum_hash;
    dap_chain_hash_fast_t block_hash;
    void *block_ref;
    time_t ts_added;
    int ret_code;
    size_t datum_index;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_net_srv_uid_t service_uid;
    int action;                 // dap_chain_tx_tag_action_type_t value (kept as int to avoid a net dependency)
    UT_hash_handle hh;
} dap_chain_state_datum_t;

typedef struct DAP_PACKED dap_chain_state_hdr {
    char magic[8];
    uint32_t version;
    uint32_t header_size;
    uint64_t net_id;
    uint64_t cell_id;
    uint64_t last_block_num;
    uint64_t blocks_count;
    uint64_t ts_saved;
    uint64_t records_count;     // block index records that follow the header
    uint64_t records_crc64;     // crc64 over all records (0 when none)
    uint64_t tx_count;          // chain-wide TX datum counter at save time
    uint64_t crc64;             // over the whole header with crc64 zeroed
    dap_chain_hash_fast_t last_block_hash;
} dap_chain_state_hdr_t;

// One block of the linear main-branch index. offset is the position of the atom
// data inside the mapped cell file (8-byte length prefix excluded); it stays 0
// for non-mapped chains, which only get the tip anchor.
typedef struct DAP_PACKED dap_chain_state_rec {
    uint64_t num;
    uint64_t ts;
    uint64_t size;
    uint64_t offset;
    dap_chain_hash_fast_t hash;
    dap_chain_hash_fast_t prev_hash;
    // v3: enough to build a thin block-cache entry without reading the body.
    uint16_t datum_count;
    uint16_t flags;
    uint32_t reserved;
} dap_chain_state_rec_t;

// Per-chain state object; the cell id selects the sidecar file.
dap_chain_state_t *dap_chain_state_create(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id);
void dap_chain_state_destroy(dap_chain_state_t *a_state);

// The sidecar path is generated on demand ("<storage dir>/<cell>.dchaincell.state").
char *dap_chain_state_path(dap_chain_state_t *a_state);

// Reads and validates the sidecar. Returns 0 and fills a_hdr on success, a
// negative reason code otherwise (magic/version/id mismatch, header CRC, file
// size vs records_count, last record vs the header tip).
int dap_chain_state_read(dap_chain_state_t *a_state, dap_chain_state_hdr_t *a_hdr);

// Last indexed block record (readiness checks: offset/size against the cell file).
bool dap_chain_state_last_record(dap_chain_state_t *a_state, dap_chain_state_rec_t *a_out);

// Walks the block index in file order (own read handle, no lock held while the
// callback runs). The callback returns false to stop. Used by the no-scan block
// cache restore.
int dap_chain_state_for_each_record(dap_chain_state_t *a_state,
        bool (*a_cb)(void *a_arg, const dap_chain_state_rec_t *a_rec), void *a_arg);

// Records one accepted block: the tip moves when a_num grows, and the block is
// appended to the index when a_index_record is true (main branch only). The
// header is flushed once per save period; readers take the tip from the last
// record.
void dap_chain_state_note_block(dap_chain_state_t *a_state, uint64_t a_num, uint64_t a_blocks_count,
                                time_t a_ts, uint64_t a_size, uint64_t a_offset,
                                const dap_chain_hash_fast_t *a_hash,
                                const dap_chain_hash_fast_t *a_prev_hash, bool a_index_record,
                                uint32_t a_datum_count);

// Forces a header write (a_sync also fsyncs and trims). Returns 0 on success,
// -2 when the chain has not opened its index yet.
int dap_chain_state_flush(dap_chain_state_t *a_state, bool a_sync);

// Closes and removes the sidecar and stops writing it for the rest of the
// process (a fork switch or an explicit 'chain cache drop state').
void dap_chain_state_drop(dap_chain_state_t *a_state);

// Datum index and chain-wide transaction counter (moved here from the blocks
// layer: both are chain-level state). add/find/remove/clear/count are safe to
// call from any thread; find copies the record out.
void dap_chain_state_datum_add(dap_chain_state_t *a_state, const dap_chain_state_datum_t *a_rec);
bool dap_chain_state_datum_find(dap_chain_state_t *a_state, const dap_chain_hash_fast_t *a_hash,
                                dap_chain_state_datum_t *a_out);
void dap_chain_state_datum_remove(dap_chain_state_t *a_state, const dap_chain_hash_fast_t *a_hash);
void dap_chain_state_datums_clear(dap_chain_state_t *a_state);
size_t dap_chain_state_datum_count(dap_chain_state_t *a_state);
// Iterator helpers over the datum index (insertion order, as before).
bool dap_chain_state_datum_first(dap_chain_state_t *a_state, dap_chain_state_datum_t *a_out);
bool dap_chain_state_datum_last(dap_chain_state_t *a_state, dap_chain_state_datum_t *a_out);
bool dap_chain_state_datum_next(dap_chain_state_t *a_state, const dap_chain_hash_fast_t *a_cur,
                                dap_chain_state_datum_t *a_out);
bool dap_chain_state_datum_prev(dap_chain_state_t *a_state, const dap_chain_hash_fast_t *a_cur,
                                dap_chain_state_datum_t *a_out);

void dap_chain_state_tx_count_set(dap_chain_state_t *a_state, uint64_t a_value);
uint64_t dap_chain_state_tx_count_get(dap_chain_state_t *a_state);
uint64_t dap_chain_state_tx_count_add(dap_chain_state_t *a_state, int64_t a_delta);

// One-line report of the sidecar (path, validity, records, tip, age).
int dap_chain_state_info(dap_chain_state_t *a_state, char *a_buf, size_t a_buf_size);

// ---- per-network state cache: id-addressed key/value entries ----
// Node-private state for services (order books, journals, shared-wallet data).
// Entries are addressed by a numeric id; the string name is only a registration
// key and is kept for snapshot output. Not the GlobalDB: no signing, no
// replication, no size limit.
typedef struct dap_chain_state_kv dap_chain_state_kv_t;
dap_chain_state_kv_t *dap_chain_state_kv_for_net(uint64_t a_net_id);
// Registers/looks up a name and returns its id (0 when absent and !a_create).
uint64_t dap_chain_state_kv_key_id(dap_chain_state_kv_t *a_kv, const char *a_name, bool a_create);
int dap_chain_state_kv_set(dap_chain_state_kv_t *a_kv, uint64_t a_id, const void *a_value, size_t a_value_len);
const void *dap_chain_state_kv_get(dap_chain_state_kv_t *a_kv, uint64_t a_id, size_t *a_value_len);
int dap_chain_state_kv_del(dap_chain_state_kv_t *a_kv, uint64_t a_id);
const char *dap_chain_state_kv_name(dap_chain_state_kv_t *a_kv, uint64_t a_id);
size_t dap_chain_state_kv_count(dap_chain_state_kv_t *a_kv);
int dap_chain_state_kv_clear(dap_chain_state_kv_t *a_kv);
typedef bool (*dap_chain_state_kv_cb_t)(void *a_arg, uint64_t a_id, const char *a_name);
int dap_chain_state_kv_foreach(dap_chain_state_kv_t *a_kv, dap_chain_state_kv_cb_t a_cb, void *a_arg);
// Snapshot payload: {net_id, next_id, count} + entries {id, ts, name, value}.
int dap_chain_state_kv_dump(uint64_t a_net_id, dap_string_t *a_out);
int dap_chain_state_kv_load(const uint8_t *a_data, size_t a_size);

// Attaches the writer to an existing sidecar after a successful index restore,
// so the first live block appends instead of truncating the restored index.
int dap_chain_state_adopt_file(dap_chain_state_t *a_state);

#ifdef __cplusplus
}
#endif
