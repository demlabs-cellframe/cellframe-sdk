/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include "uthash.h"
#include "dap_chain.h"
#include "dap_chain_common.h"

// One lazy-read window: a read-only mapping of a file range, kept until the cell
// is closed (a body pointer handed out earlier must stay valid).
typedef struct dap_chain_cell_read_win {
    void *ptr;             // mapping base
    size_t file_start;     // absolute file offset the window starts at
    size_t len;            // mapped length, page rounded
} dap_chain_cell_read_win_t;

typedef struct dap_chain_cell {
    dap_chain_cell_id_t id;
    dap_chain_t * chain;

    char file_storage_path[MAX_PATH];
    char *map, *map_pos, *map_end;
    FILE *file_storage;
    uint8_t file_storage_type;
    dap_list_t *map_range_bounds;
    // Absolute file position the current mmap window starts at: block pointers
    // are window-relative, persisted offsets must be absolute.
    size_t cur_vol_start;
    // Lazy-read window: bodies of thin (index-restored) blocks are served IN
    // PLACE from a read-only file mapping instead of being copied into the heap.
    // A private heap copy per touched body pinned one full cell file per walk
    // (measured on cf-mm-0: two malloc arenas held ~15 GB each, one per network,
    // with only 300 MB of free chunks). This window is deliberately separate
    // from map/map_pos/map_end above: those are the loader/append cursor, they
    // are mutated without a lock by the loader, and a lazy reader must never
    // move the append position (the next live block is taken at map_pos).
    // Windows are never unmapped while the cell lives; an earlier window's pages
    // are advised away when a new one is mapped (clean file pages re-fault from
    // disk). read_windows holds dap_chain_cell_read_win_t entries so that a
    // lookup can tell whether an already mapped window covers the range.
    char *read_map;
    size_t read_map_start;     // absolute file offset read_map starts at
    size_t read_map_size;      // read_map length, page rounded
    int read_fd;               // private read-only fd for the lazy windows (-1 = none)
    dap_list_t *read_windows;  // dap_chain_cell_read_win_t*, ownership of all windows
    pthread_mutex_t read_map_mutex;
    pthread_rwlock_t storage_rwlock;
    UT_hash_handle hh;
} dap_chain_cell_t;

/**
 *
 */
#define DAP_CHAIN_CELL_DECL_REQ_SIGN_SIZE 32
typedef struct dap_chain_cell_delc_req {
    dap_chain_addr_t wallet_address;  // Need new wallet address where the hold coins should be directed. Must have undefined cell
    uint64_t create_ts;
    union{
        uint8_t raw[DAP_CHAIN_CELL_DECL_REQ_SIGN_SIZE];
        char str[DAP_CHAIN_CELL_DECL_REQ_SIGN_SIZE];
    } info;
} DAP_ALIGN_PACKED dap_chain_cell_decl_req_t;

/**
  * @struct dap_chain_cell_decl
  * @details New cell declaration
  *
  */
#define DAP_CHAIN_CELL_DECL_ACCEPT_INFO_SIZE 32
typedef struct dap_chain_cell_decl{
    dap_chain_cell_decl_req_t request;
    dap_chain_cell_id_t cell_id;
    uint64_t accept_ts;
    union{
        uint8_t raw[DAP_CHAIN_CELL_DECL_ACCEPT_INFO_SIZE];
        char str[DAP_CHAIN_CELL_DECL_ACCEPT_INFO_SIZE];
    } accept_info;
} DAP_ALIGN_PACKED dap_chain_cell_decl_t;


int dap_chain_cell_init(void);
dap_chain_cell_t *dap_chain_cell_create_fill(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id);
dap_chain_cell_t *dap_chain_cell_find_by_id(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id);
// Maps the file window containing a_file_pos (used by the index restore and the
// lazy block parser). No-op when the current window already covers it.
int dap_chain_cell_map_window(dap_chain_cell_t *a_cell, size_t a_file_pos);
// Same, but always remaps so the atom at a_file_pos starts inside the new window
// (an atom crossing the current window end cannot be used in place).
int dap_chain_cell_map_window_force(dap_chain_cell_t *a_cell, size_t a_file_pos);
// Absolute file offset of the atom the non-mapped loader is currently feeding
// (thread-local; 0 when not in a load pass).
uint64_t dap_chain_cell_load_offset(void);
// Body of the atom the loader is feeding right now, returned only when the
// request matches it exactly. A scan-created block cache entry stays thin and
// parses its body from bytes the loader has already read instead of faulting the
// same range in a second time (NULL when the hint does not match).
const uint8_t *dap_chain_cell_load_hint_view(size_t a_file_offset, size_t a_size);
// Drops the resident pages of the loader's mmap volumes, keeping the one that
// holds a_keep_ptr (the range the caller is walking right now; pass NULL when
// there is none) and the one at the loader's append cursor. The mappings - and
// every pointer into them - stay valid; only residency is returned to the
// kernel, so a 20 GB scan no longer leaves ~9 GB of cell mappings resident for
// the rest of the run. Called by whole-chain walks and after a load pass.
void dap_chain_cell_volumes_trim(dap_chain_cell_t *a_cell, const void *a_keep_ptr);
// Bounded variant: only pages below a_upto (an absolute file position) are
// advised away. The loader rounds its volume up to the full 256 MB, so a
// mapping can extend past EOF; dropping such a page and then touching it is a
// SIGBUS, while pages below the file size always re-fault from the file.
void dap_chain_cell_volumes_trim_upto(dap_chain_cell_t *a_cell, size_t a_upto);
// Borrowed view of a byte range of the cell file: the range is served from a
// read-only file mapping, so a lazy body read costs page-cache pages instead of
// a private heap copy. Pages of a previous window are advised away (they are
// clean and re-fault from the file on the next access), the mapping itself is
// kept until the cell is closed - a returned pointer stays valid for the cell's
// lifetime and its contents never change (the file is only appended to).
// Returns NULL when the range is outside the file or the view cannot be set up
// (callers fall back to their own buffer).
const uint8_t *dap_chain_cell_body_view(dap_chain_cell_t *a_cell, size_t a_file_offset, size_t a_size);
// Borrowed view of a range that lies inside one of the LOADER's volumes. Those
// mappings live as long as the cell (the loader only ever adds volumes), so a
// pointer from here may be KEPT in a long-lived structure - the block cache
// stores it as the entry's body. Returns NULL when no existing volume covers the
// range, which is the normal case on a no-scan start; the caller then copies.
const uint8_t *dap_chain_cell_volume_view(dap_chain_cell_t *a_cell, size_t a_file_offset, size_t a_size);
// Mapped/borrowed byte ranges currently held by lazy reads, for accounting.
void dap_chain_cell_read_window_stats(dap_chain_cell_t *a_cell, size_t *a_window_bytes, size_t *a_views);
// Releases every lazy-read window. Called when the file is rewritten in place
// (rewind/purge) - the bytes behind those mappings are gone. Only purge paths,
// which also clear the block cache, may call it: no cache entry can keep a body
// pointer into a dropped window.
void dap_chain_cell_read_windows_drop(dap_chain_cell_t *a_cell);
 // File offset of the first atom body in a cell file (past the cell header and
// its 8-byte length prefix). A state index whose first record is not here does
// not cover the file from its start.
size_t dap_chain_cell_first_atom_offset(void);
void dap_chain_cell_close(dap_chain_cell_t *a_cell);
void dap_chain_cell_delete(dap_chain_cell_t *a_cell);
void dap_chain_cell_delete_all_and_free_file(dap_chain_t *a_chain);
void dap_chain_cell_delete_all(dap_chain_t *a_chain);
int dap_chain_cell_load(dap_chain_t *a_chain, dap_chain_cell_t *a_cell);
ssize_t dap_chain_cell_file_append(dap_chain_cell_t *a_cell,const void *a_atom, size_t a_atom_size);
DAP_STATIC_INLINE ssize_t dap_chain_cell_file_update(dap_chain_cell_t *a_cell) {
    return dap_chain_cell_file_append(a_cell, NULL, 0);
}