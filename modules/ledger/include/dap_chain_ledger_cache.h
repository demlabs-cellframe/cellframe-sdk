/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2026, All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 *
 *    CellFrame SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    CellFrame SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_chain_common.h"
#include "dap_math_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DAP_LEDGER_CACHE_MAGIC          0x4441504341434845ULL   /* "DAPCACHE" */
#define DAP_LEDGER_CACHE_VERSION        1
#define DAP_LEDGER_CACHE_HEADER_SIZE    120
#define DAP_LEDGER_CACHE_RECORD_HDR_SIZE 8
#define DAP_LEDGER_CACHE_INITIAL_SIZE   (64ULL * 1024 * 1024) /* 64 MB */

/*
 * Headroom: minimum free space between data_end and mapped_size.
 * When a new record would leave less than HEADROOM bytes free, the file
 * is extended with ftruncate + remapped (2× growth factor).  "Headroom"
 * refers to both the file size (on-disk pages lazily allocated by the
 * kernel via MAP_SHARED) and the virtual address range.  There is no
 * separate heap or anonymous allocation for this space.
 */
#define DAP_LEDGER_CACHE_HEADROOM       (4ULL * 1024 * 1024)  /* 4 MB  */

#define DAP_LEDGER_CACHE_DIRTY_CLEAN    0
#define DAP_LEDGER_CACHE_DIRTY_DIRTY    1

typedef enum {
    DAP_LEDGER_CACHE_REC_TX           = 1,
    DAP_LEDGER_CACHE_REC_TOKEN        = 2,
    DAP_LEDGER_CACHE_REC_EMISSION     = 3,
    DAP_LEDGER_CACHE_REC_STAKE_LOCK   = 4,
    DAP_LEDGER_CACHE_REC_TOKEN_UPDATE = 5,
    DAP_LEDGER_CACHE_REC_MAX          = 5
} dap_ledger_cache_record_type_t;

/* Minimum sizes per record type (including 8 B record header) */
#define DAP_LEDGER_CACHE_TX_MIN_SIZE          136
#define DAP_LEDGER_CACHE_TOKEN_SIZE           128
#define DAP_LEDGER_CACHE_EMISSION_SIZE        136
#define DAP_LEDGER_CACHE_STAKE_LOCK_SIZE       80
#define DAP_LEDGER_CACHE_TOKEN_UPDATE_SIZE    104

/*
 * File Header — 120 bytes, all multi-byte fields little-endian.
 */
typedef struct dap_ledger_cache_file_header {
    uint64_t    magic;              /*  0 */
    uint32_t    version;            /*  8 */
    uint32_t    dirty_flag;         /* 12 */
    uint64_t    record_count;       /* 16 */
    uint64_t    data_end;           /* 24 */
    uint64_t    net_id;             /* 32 */
    uint64_t    manifest_count;     /* 40 — number of manifest entries written at shutdown */
    uint8_t     reserved[32];       /* 48 */
    uint8_t     manifest_hash[32];  /* 80 — SHA3-256 */
    uint64_t    created_at;         /* 112 — dap_nanotime_t */
} __attribute__((packed)) dap_ledger_cache_file_header_t;

_Static_assert(sizeof(dap_ledger_cache_file_header_t) == DAP_LEDGER_CACHE_HEADER_SIZE,
               "File header must be exactly 120 bytes");

/*
 * Record Header — 8 bytes, ensures 8-byte alignment for body fields.
 */
typedef struct dap_ledger_cache_record_hdr {
    uint32_t    record_size;        /* Total record size including this header */
    uint8_t     record_type;        /* dap_ledger_cache_record_type_t */
    uint8_t     pad[3];             /* Zero padding for alignment */
} __attribute__((packed)) dap_ledger_cache_record_hdr_t;

_Static_assert(sizeof(dap_ledger_cache_record_hdr_t) == DAP_LEDGER_CACHE_RECORD_HDR_SIZE,
               "Record header must be exactly 8 bytes");

/*
 * TX Record — type 1, 136 B fixed + n_outs * 32 B.
 * Includes datum_file_offset per design Section 14 (Option 1).
 */
typedef struct dap_ledger_cache_tx_record {
    dap_ledger_cache_record_hdr_t hdr;              /*   0 -  8 B */
    dap_hash_fast_t     tx_hash_fast;                /*   8 - 32 B */
    uint64_t            ts_added;                    /*  40 -  8 B (dap_nanotime_t) */
    uint64_t            ts_created;                  /*  48 -  8 B (dap_time_t) */
    uint32_t            n_outs;                      /*  56 -  4 B */
    uint32_t            n_outs_used;                 /*  60 -  4 B (mutable) */
    char                token_ticker[10];            /*  64 - 10 B */
    uint8_t             flags;                       /*  74 -  1 B */
    uint8_t             tombstone;                   /*  75 -  1 B */
    uint32_t            pad;                         /*  76 -  4 B */
    uint64_t            ts_spent;                    /*  80 -  8 B (mutable, dap_time_t) */
    uint64_t            tag;                         /*  88 -  8 B (dap_chain_srv_uid_t) */
    uint32_t            action;                      /*  96 -  4 B */
    uint32_t            pad2;                        /* 100 -  4 B */
    uint64_t            datum_size;                  /* 104 -  8 B */
    uint64_t            chain_id;                    /* 112 -  8 B */
    uint64_t            cell_id;                     /* 120 -  8 B */
    uint64_t            datum_file_offset;           /* 128 -  8 B */
    dap_hash_fast_t     out_spent_hashes[];          /* 136+ - n_outs * 32 B (mutable) */
} __attribute__((packed)) dap_ledger_cache_tx_record_t;

_Static_assert(sizeof(dap_ledger_cache_tx_record_t) == DAP_LEDGER_CACHE_TX_MIN_SIZE,
               "TX record base must be exactly 136 bytes");

/*
 * Token Record — type 2, 128 B fixed.
 */
typedef struct dap_ledger_cache_token_record {
    dap_ledger_cache_record_hdr_t hdr;              /*   0 -  8 B */
    dap_hash_fast_t     token_hash;                  /*   8 - 32 B */
    char                ticker[10];                  /*  40 - 10 B */
    uint16_t            subtype;                     /*  50 -  2 B */
    uint32_t            pad;                         /*  52 -  4 B */
    uint256_t           current_supply;              /*  56 - 32 B (mutable) */
    uint64_t            datum_size;                  /*  88 -  8 B */
    uint64_t            chain_id;                    /*  96 -  8 B */
    uint64_t            cell_id;                     /* 104 -  8 B */
    uint64_t            datum_file_offset;           /* 112 -  8 B */
    uint8_t             tombstone;                   /* 120 -  1 B */
    uint8_t             reserved[7];                 /* 121 -  7 B */
} __attribute__((packed)) dap_ledger_cache_token_record_t;

_Static_assert(sizeof(dap_ledger_cache_token_record_t) == DAP_LEDGER_CACHE_TOKEN_SIZE,
               "Token record must be exactly 128 bytes");

/*
 * Emission Record — type 3, 136 B fixed.
 */
typedef struct dap_ledger_cache_emission_record {
    dap_ledger_cache_record_hdr_t hdr;              /*   0 -  8 B */
    dap_hash_fast_t     datum_token_emission_hash;   /*   8 - 32 B */
    dap_hash_fast_t     tx_used_out;                 /*  40 - 32 B (mutable) */
    char                ticker[10];                  /*  72 - 10 B */
    uint8_t             pad[6];                      /*  82 -  6 B */
    uint64_t            ts_added;                    /*  88 -  8 B (dap_nanotime_t) */
    uint64_t            datum_size;                  /*  96 -  8 B */
    uint64_t            chain_id;                    /* 104 -  8 B */
    uint64_t            cell_id;                     /* 112 -  8 B */
    uint64_t            datum_file_offset;           /* 120 -  8 B */
    uint8_t             tombstone;                   /* 128 -  1 B */
    uint8_t             is_hardfork;                 /* 129 -  1 B */
    uint8_t             reserved[6];                 /* 130 -  6 B */
} __attribute__((packed)) dap_ledger_cache_emission_record_t;

_Static_assert(sizeof(dap_ledger_cache_emission_record_t) == DAP_LEDGER_CACHE_EMISSION_SIZE,
               "Emission record must be exactly 136 bytes");

/*
 * Stake Lock Record — type 4, 80 B fixed.
 */
typedef struct dap_ledger_cache_stake_lock_record {
    dap_ledger_cache_record_hdr_t hdr;              /*   0 -  8 B */
    dap_hash_fast_t     tx_for_stake_lock_hash;      /*   8 - 32 B */
    dap_hash_fast_t     tx_used_out;                 /*  40 - 32 B (mutable) */
    uint64_t            datum_file_offset;           /*  72 -  8 B */
} __attribute__((packed)) dap_ledger_cache_stake_lock_record_t;

_Static_assert(sizeof(dap_ledger_cache_stake_lock_record_t) == DAP_LEDGER_CACHE_STAKE_LOCK_SIZE,
               "Stake lock record must be exactly 80 bytes");

/*
 * Token Update Record — type 5, 104 B fixed.
 */
typedef struct dap_ledger_cache_token_update_record {
    dap_ledger_cache_record_hdr_t hdr;              /*   0 -  8 B */
    dap_hash_fast_t     update_token_hash;           /*   8 - 32 B */
    char                ticker[10];                  /*  40 - 10 B */
    uint16_t            pad;                         /*  50 -  2 B */
    uint32_t            pad2;                        /*  52 -  4 B */
    uint64_t            datum_size;                  /*  56 -  8 B */
    uint64_t            updated_time;                /*  64 -  8 B */
    uint64_t            chain_id;                    /*  72 -  8 B */
    uint64_t            cell_id;                     /*  80 -  8 B */
    uint64_t            datum_file_offset;           /*  88 -  8 B */
    uint8_t             tombstone;                   /*  96 -  1 B */
    uint8_t             reserved[7];                 /*  97 -  7 B */
} __attribute__((packed)) dap_ledger_cache_token_update_record_t;

_Static_assert(sizeof(dap_ledger_cache_token_update_record_t) == DAP_LEDGER_CACHE_TOKEN_UPDATE_SIZE,
               "Token update record must be exactly 104 bytes");

/*
 * Manifest Entry — 56 B, written at data_end during shutdown.
 */
typedef struct dap_ledger_cache_manifest_entry {
    uint64_t            chain_id;                    /*  0 -  8 B */
    uint64_t            cell_id;                     /*  8 -  8 B */
    dap_hash_fast_t     last_atom_hash;              /* 16 - 32 B */
    uint64_t            atom_count;                  /* 48 -  8 B */
} __attribute__((packed)) dap_ledger_cache_manifest_entry_t;

_Static_assert(sizeof(dap_ledger_cache_manifest_entry_t) == 56,
               "Manifest entry must be exactly 56 bytes");

/*
 * Callback for scanner — called for each valid record during scan.
 */
typedef int (*dap_ledger_cache_scan_callback_t)(
    const dap_ledger_cache_record_hdr_t *a_record_hdr,
    uint64_t a_offset,
    void *a_user_data
);

/*
 * Runtime context for an open cache file.
 */
typedef struct dap_ledger_cache {
    int         fd;
    uint8_t     *base;              /* mmap base address */
    uint64_t    mapped_size;        /* current mmap window size */
    uint64_t    data_end;           /* next append point */
    uint64_t    record_count;       /* total records appended */
    char        *file_path;         /* path to .lcache file */
    bool        dirty;              /* runtime dirty tracking */
} dap_ledger_cache_t;

/* ---- Public API ---- */

/**
 * Open or create a cache file. On success returns 0 and fills *a_cache.
 * a_net_id is stored in the header when creating a new file.
 */
int  dap_ledger_cache_open(dap_ledger_cache_t *a_cache, const char *a_path, uint64_t a_net_id);

/**
 * Close the cache file without writing a clean shutdown (leaves DIRTY).
 */
void dap_ledger_cache_close(dap_ledger_cache_t *a_cache);

/**
 * Read the file header from an open cache. Returns 0 on success.
 */
int  dap_ledger_cache_read_header(dap_ledger_cache_t *a_cache, dap_ledger_cache_file_header_t *a_hdr);

/**
 * Mark cache as DIRTY and msync the header page.
 */
int  dap_ledger_cache_mark_dirty(dap_ledger_cache_t *a_cache);

/**
 * Append a raw record to the cache. Ensures headroom, extends file if needed.
 * Returns offset of the new record on success, (uint64_t)-1 on error.
 */
uint64_t dap_ledger_cache_append(dap_ledger_cache_t *a_cache, const void *a_record, uint32_t a_record_size);

/**
 * Scan all records in the cache file, calling a_callback for each valid record.
 * Returns the number of valid records scanned, or -1 on error.
 * If a_truncate_on_error is true, truncates data_end at first invalid record.
 */
int64_t dap_ledger_cache_scan(dap_ledger_cache_t *a_cache, dap_ledger_cache_scan_callback_t a_callback,
                              void *a_user_data, bool a_truncate_on_error);

/**
 * Validate a record header at the given offset.
 * Returns 0 if valid, non-zero if invalid.
 */
int  dap_ledger_cache_validate_record(const uint8_t *a_base, uint64_t a_offset, uint64_t a_data_end);

/**
 * Write manifest and close cleanly (dirty_flag = CLEAN).
 * Implements the shutdown sequence from design Section 9.5.
 */
int  dap_ledger_cache_shutdown(dap_ledger_cache_t *a_cache,
                               const dap_ledger_cache_manifest_entry_t *a_manifest_entries,
                               size_t a_manifest_count);

/**
 * Validate manifest hash after reading from a CLEAN cache.
 * Checks magic, version, dirty_flag, data_end bounds, manifest_hash,
 * and optionally record_count consistency.
 * Returns 0 if manifest is valid.
 */
int  dap_ledger_cache_validate_manifest(dap_ledger_cache_t *a_cache);

/**
 * Compact the cache: remove tombstoned records, rewrite to a clean file.
 * Performs atomic rename(temp, original) with full fsync sequence.
 * On success, a_cache is remapped to the compacted file.
 * Returns 0 on success, -1 on error.
 */
int  dap_ledger_cache_compact(dap_ledger_cache_t *a_cache,
                              const dap_ledger_cache_manifest_entry_t *a_manifest_entries,
                              size_t a_manifest_count);

/**
 * Purge (reset) the cache: truncate to header-only state.
 * All records are discarded and the cache is ready for fresh appends.
 * Returns 0 on success, -1 on error.
 */
int  dap_ledger_cache_purge(dap_ledger_cache_t *a_cache);

/**
 * Ensure there is at least a_needed bytes of space after data_end.
 * May resize the file and remap.
 * Returns 0 on success, -1 on error.
 */
int  dap_ledger_cache_ensure_headroom(dap_ledger_cache_t *a_cache, uint64_t a_needed);

/**
 * Get a pointer to a record at the given offset.
 */
DAP_STATIC_INLINE const dap_ledger_cache_record_hdr_t *
dap_ledger_cache_record_at(const dap_ledger_cache_t *a_cache, uint64_t a_offset)
{
    if (a_offset + DAP_LEDGER_CACHE_RECORD_HDR_SIZE > a_cache->data_end)
        return NULL;
    return (const dap_ledger_cache_record_hdr_t *)(a_cache->base + a_offset);
}

/**
 * Get the minimum expected record body size for a given record type.
 * Returns 0 for unknown types.
 */
DAP_STATIC_INLINE uint32_t
dap_ledger_cache_min_record_size(uint8_t a_record_type)
{
    switch (a_record_type) {
        case DAP_LEDGER_CACHE_REC_TX:           return DAP_LEDGER_CACHE_TX_MIN_SIZE;
        case DAP_LEDGER_CACHE_REC_TOKEN:        return DAP_LEDGER_CACHE_TOKEN_SIZE;
        case DAP_LEDGER_CACHE_REC_EMISSION:     return DAP_LEDGER_CACHE_EMISSION_SIZE;
        case DAP_LEDGER_CACHE_REC_STAKE_LOCK:   return DAP_LEDGER_CACHE_STAKE_LOCK_SIZE;
        case DAP_LEDGER_CACHE_REC_TOKEN_UPDATE: return DAP_LEDGER_CACHE_TOKEN_UPDATE_SIZE;
        default:                                return 0;
    }
}

/**
 * Check if a record at the given offset is tombstoned.
 * Stake-lock records have no tombstone field and always return false.
 * Unknown record types also return false.
 */
DAP_STATIC_INLINE bool
dap_ledger_cache_record_is_tombstoned(const uint8_t *a_base, uint64_t a_offset)
{
    const dap_ledger_cache_record_hdr_t *l_hdr =
        (const dap_ledger_cache_record_hdr_t *)(a_base + a_offset);
    switch (l_hdr->record_type) {
        case DAP_LEDGER_CACHE_REC_TX: {
            const dap_ledger_cache_tx_record_t *l_tx =
                (const dap_ledger_cache_tx_record_t *)(a_base + a_offset);
            return l_tx->tombstone != 0;
        }
        case DAP_LEDGER_CACHE_REC_TOKEN: {
            const dap_ledger_cache_token_record_t *l_tok =
                (const dap_ledger_cache_token_record_t *)(a_base + a_offset);
            return l_tok->tombstone != 0;
        }
        case DAP_LEDGER_CACHE_REC_EMISSION: {
            const dap_ledger_cache_emission_record_t *l_em =
                (const dap_ledger_cache_emission_record_t *)(a_base + a_offset);
            return l_em->tombstone != 0;
        }
        case DAP_LEDGER_CACHE_REC_TOKEN_UPDATE: {
            const dap_ledger_cache_token_update_record_t *l_upd =
                (const dap_ledger_cache_token_update_record_t *)(a_base + a_offset);
            return l_upd->tombstone != 0;
        }
        default:
            return false;
    }
}

/* ---- Higher-level record append helpers ---- */

/**
 * Append a TX record to the cache. Returns the file offset of the new record,
 * or (uint64_t)-1 on error.
 */
uint64_t dap_ledger_cache_append_tx_record(dap_ledger_cache_t *a_cache,
                                           const dap_hash_fast_t *a_tx_hash,
                                           uint64_t a_ts_added,
                                           uint64_t a_ts_created,
                                           uint32_t a_n_outs,
                                           uint32_t a_n_outs_used,
                                           const char a_token_ticker[10],
                                           uint8_t a_flags,
                                           uint8_t a_tombstone,
                                           uint64_t a_ts_spent,
                                           uint64_t a_tag,
                                           uint32_t a_action,
                                           uint64_t a_datum_size,
                                           uint64_t a_chain_id,
                                           uint64_t a_cell_id,
                                           uint64_t a_datum_file_offset,
                                           const dap_hash_fast_t *a_out_spent_hashes);

/**
 * Append a Token record. Returns offset or (uint64_t)-1.
 */
uint64_t dap_ledger_cache_append_token_record(dap_ledger_cache_t *a_cache,
                                              const dap_hash_fast_t *a_token_hash,
                                              const char a_ticker[10],
                                              uint16_t a_subtype,
                                              const uint256_t *a_current_supply,
                                              uint64_t a_datum_size,
                                              uint64_t a_chain_id,
                                              uint64_t a_cell_id,
                                              uint64_t a_datum_file_offset);

/**
 * Append an Emission record. Returns offset or (uint64_t)-1.
 */
uint64_t dap_ledger_cache_append_emission_record(dap_ledger_cache_t *a_cache,
                                                 const dap_hash_fast_t *a_emission_hash,
                                                 const char a_ticker[10],
                                                 uint64_t a_ts_added,
                                                 uint64_t a_datum_size,
                                                 uint64_t a_chain_id,
                                                 uint64_t a_cell_id,
                                                 uint64_t a_datum_file_offset,
                                                 bool a_is_hardfork);

/**
 * Append a Stake Lock record. Returns offset or (uint64_t)-1.
 */
uint64_t dap_ledger_cache_append_stake_lock_record(dap_ledger_cache_t *a_cache,
                                                   const dap_hash_fast_t *a_stake_lock_hash,
                                                   uint64_t a_datum_file_offset);

/**
 * Append a Token Update record. Returns offset or (uint64_t)-1.
 */
uint64_t dap_ledger_cache_append_token_update_record(dap_ledger_cache_t *a_cache,
                                                     const dap_hash_fast_t *a_update_hash,
                                                     const char a_ticker[10],
                                                     uint64_t a_datum_size,
                                                     uint64_t a_updated_time,
                                                     uint64_t a_chain_id,
                                                     uint64_t a_cell_id,
                                                     uint64_t a_datum_file_offset);

/* ---- In-place mutable field updates ---- */

/**
 * Update TX spent status in-place. a_record_offset is the offset returned by append.
 */
int dap_ledger_cache_update_tx_spent(dap_ledger_cache_t *a_cache,
                                     uint64_t a_record_offset,
                                     uint32_t a_out_idx,
                                     const dap_hash_fast_t *a_spender_hash,
                                     uint32_t a_n_outs_used,
                                     uint64_t a_ts_spent);

/**
 * Update emission tx_used_out in-place.
 */
int dap_ledger_cache_update_emission_spent(dap_ledger_cache_t *a_cache,
                                           uint64_t a_record_offset,
                                           const dap_hash_fast_t *a_tx_hash);

/**
 * Update stake lock tx_used_out in-place.
 */
int dap_ledger_cache_update_stake_lock_spent(dap_ledger_cache_t *a_cache,
                                             uint64_t a_record_offset,
                                             const dap_hash_fast_t *a_tx_hash);

/**
 * Update token current_supply in-place.
 */
int dap_ledger_cache_update_token_supply(dap_ledger_cache_t *a_cache,
                                         uint64_t a_record_offset,
                                         const uint256_t *a_new_supply);

/**
 * Set tombstone flag on a TX record.
 */
int dap_ledger_cache_tombstone_tx(dap_ledger_cache_t *a_cache, uint64_t a_record_offset);

/* ---- Warm startup scan ---- */

/**
 * Per-type callbacks for warm startup scan.
 * Each callback receives a typed pointer to the record in the mmap region,
 * the file offset of the record, and user data.
 * Return 0 to continue scanning, non-zero to abort.
 * Tombstoned records are automatically skipped and not delivered to callbacks.
 */
typedef struct {
    int (*on_token)(const dap_ledger_cache_token_record_t *a_rec,
                    uint64_t a_offset, void *a_user_data);
    int (*on_emission)(const dap_ledger_cache_emission_record_t *a_rec,
                       uint64_t a_offset, void *a_user_data);
    int (*on_stake_lock)(const dap_ledger_cache_stake_lock_record_t *a_rec,
                         uint64_t a_offset, void *a_user_data);
    int (*on_tx)(const dap_ledger_cache_tx_record_t *a_rec,
                 uint64_t a_offset, void *a_user_data);
    int (*on_token_update)(const dap_ledger_cache_token_update_record_t *a_rec,
                           uint64_t a_offset, void *a_user_data);
    void *user_data;
} dap_ledger_cache_warm_load_callbacks_t;

/**
 * Warm startup load from a CLEAN cache file.
 *
 * 1. Validates the manifest (magic, version, dirty_flag, hashes, record_count).
 * 2. Scans all records sequentially, dispatching to per-type callbacks.
 *    Tombstoned records are skipped. Unknown types are silently skipped.
 * 3. On success, sets dirty_flag = DIRTY and msyncs the header so that
 *    any crash during normal operation triggers a cold rebuild.
 *
 * Returns 0 on success, negative on error:
 *   -1: invalid arguments
 *   -2: manifest validation failed (cache is dirty or corrupt)
 *   -3: callback returned non-zero (aborted)
 *   -4: corrupt record encountered during scan
 */
int dap_ledger_cache_warm_load(dap_ledger_cache_t *a_cache,
                               const dap_ledger_cache_warm_load_callbacks_t *a_callbacks);

#ifdef __cplusplus
}
#endif
