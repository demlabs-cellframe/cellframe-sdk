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
#include "uthash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DAP_CHAIN_STATE_VERSION 2
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

// Records one accepted block: the tip moves when a_num grows, and the block is
// appended to the index when a_index_record is true (main branch only). The
// header is rewritten after every append; fsync and torn-tail trimming happen
// once per save period.
void dap_chain_state_note_block(dap_chain_state_t *a_state, uint64_t a_num, uint64_t a_blocks_count,
                                time_t a_ts, uint64_t a_size, uint64_t a_offset,
                                const dap_chain_hash_fast_t *a_hash,
                                const dap_chain_hash_fast_t *a_prev_hash, bool a_index_record);

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

#ifdef __cplusplus
}
#endif
