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

#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_ledger_cache.h"

#define LOG_TAG "dap_ledger_cache"

/*
 * Threading model: Option A (single-threaded atom processing).
 *
 * All cache mutations (append, in-place updates, remap) are called from the
 * ledger layer during atom processing, which is serialized by the network
 * loading loop (one atom at a time).  No internal locking is needed for the
 * cache file because concurrent mutation never occurs.
 *
 * If atom processing is ever parallelized, a cache-level lock must be added
 * around all append, update, and remap operations.
 */

static int s_cache_remap(dap_ledger_cache_t *a_cache, uint64_t a_new_size);

int dap_ledger_cache_open(dap_ledger_cache_t *a_cache, const char *a_path, uint64_t a_net_id)
{
    if (!a_cache || !a_path)
        return -1;

    memset(a_cache, 0, sizeof(*a_cache));
    a_cache->fd = -1;

    bool l_creating = false;
    struct stat l_st;
    if (stat(a_path, &l_st) != 0) {
        if (errno == ENOENT)
            l_creating = true;
        else {
            log_it(L_ERROR, "stat(%s) failed: %s", a_path, strerror(errno));
            return -1;
        }
    }

    int l_fd = open(a_path, O_RDWR | O_CREAT, 0644);
    if (l_fd < 0) {
        log_it(L_ERROR, "open(%s) failed: %s", a_path, strerror(errno));
        return -1;
    }

    uint64_t l_file_size;
    if (l_creating || l_st.st_size < (off_t)DAP_LEDGER_CACHE_HEADER_SIZE) {
        l_file_size = DAP_LEDGER_CACHE_INITIAL_SIZE;
        if (ftruncate(l_fd, (off_t)l_file_size) != 0) {
            log_it(L_ERROR, "ftruncate(%s, %llu) failed: %s", a_path,
                   (unsigned long long)l_file_size, strerror(errno));
            close(l_fd);
            return -1;
        }
    } else {
        l_file_size = (uint64_t)l_st.st_size;
    }

    uint8_t *l_base = mmap(NULL, l_file_size, PROT_READ | PROT_WRITE, MAP_SHARED, l_fd, 0);
    if (l_base == MAP_FAILED) {
        log_it(L_ERROR, "mmap(%s, %llu) failed: %s", a_path,
               (unsigned long long)l_file_size, strerror(errno));
        close(l_fd);
        return -1;
    }

    a_cache->fd = l_fd;
    a_cache->base = l_base;
    a_cache->mapped_size = l_file_size;
    a_cache->file_path = strdup(a_path);

    if (l_creating || l_st.st_size < (off_t)DAP_LEDGER_CACHE_HEADER_SIZE) {
        /* Write fresh header */
        dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_base;
        memset(l_hdr, 0, sizeof(*l_hdr));
        l_hdr->magic = DAP_LEDGER_CACHE_MAGIC;
        l_hdr->version = DAP_LEDGER_CACHE_VERSION;
        l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;
        l_hdr->record_count = 0;
        l_hdr->data_end = DAP_LEDGER_CACHE_HEADER_SIZE;
        l_hdr->net_id = a_net_id;
        l_hdr->created_at = (uint64_t)dap_nanotime_now();
        a_cache->data_end = DAP_LEDGER_CACHE_HEADER_SIZE;
        a_cache->record_count = 0;
        a_cache->dirty = true;
    } else {
        /* Read existing header, clamping data_end to prevent OOB access */
        dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_base;
        a_cache->data_end = l_hdr->data_end <= l_file_size ? l_hdr->data_end : l_file_size;
        a_cache->record_count = l_hdr->record_count;
        a_cache->dirty = (l_hdr->dirty_flag != DAP_LEDGER_CACHE_DIRTY_CLEAN);
    }

    return 0;
}

void dap_ledger_cache_close(dap_ledger_cache_t *a_cache)
{
    if (!a_cache)
        return;

    if (a_cache->base && a_cache->base != MAP_FAILED) {
        munmap(a_cache->base, a_cache->mapped_size);
        a_cache->base = NULL;
    }
    if (a_cache->fd >= 0) {
        close(a_cache->fd);
        a_cache->fd = -1;
    }
    if (a_cache->file_path) {
        free(a_cache->file_path);
        a_cache->file_path = NULL;
    }
    a_cache->mapped_size = 0;
    a_cache->data_end = 0;
    a_cache->record_count = 0;
}

int dap_ledger_cache_read_header(dap_ledger_cache_t *a_cache, dap_ledger_cache_file_header_t *a_hdr)
{
    if (!a_cache || !a_cache->base || !a_hdr)
        return -1;
    if (a_cache->mapped_size < DAP_LEDGER_CACHE_HEADER_SIZE)
        return -1;

    memcpy(a_hdr, a_cache->base, sizeof(*a_hdr));
    return 0;
}

int dap_ledger_cache_mark_dirty(dap_ledger_cache_t *a_cache)
{
    if (!a_cache || !a_cache->base)
        return -1;

    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)a_cache->base;
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;
    a_cache->dirty = true;

    long l_page_size = sysconf(_SC_PAGESIZE);
    if (l_page_size <= 0)
        l_page_size = 4096;
    if (msync(a_cache->base, (size_t)l_page_size, MS_SYNC) != 0) {
        log_it(L_ERROR, "msync header failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int dap_ledger_cache_ensure_headroom(dap_ledger_cache_t *a_cache, uint64_t a_needed)
{
    if (!a_cache)
        return -1;

    if (a_cache->data_end + a_needed + DAP_LEDGER_CACHE_HEADROOM <= a_cache->mapped_size)
        return 0;

    uint64_t l_new_size = a_cache->mapped_size * 2;
    uint64_t l_min_size = a_cache->data_end + a_needed + DAP_LEDGER_CACHE_HEADROOM;
    if (l_new_size < l_min_size)
        l_new_size = l_min_size;

    return s_cache_remap(a_cache, l_new_size);
}

static int s_cache_remap(dap_ledger_cache_t *a_cache, uint64_t a_new_size)
{
    if (ftruncate(a_cache->fd, (off_t)a_new_size) != 0) {
        log_it(L_ERROR, "ftruncate(%llu) failed: %s",
               (unsigned long long)a_new_size, strerror(errno));
        return -1;
    }

#ifdef __linux__
    uint8_t *l_new_base = mremap(a_cache->base, a_cache->mapped_size,
                                  a_new_size, MREMAP_MAYMOVE);
    if (l_new_base == MAP_FAILED) {
        log_it(L_WARNING, "mremap failed, falling back to mmap: %s", strerror(errno));
    } else {
        a_cache->base = l_new_base;
        a_cache->mapped_size = a_new_size;
        return 0;
    }
#endif

    /* Fallback: map new region at kernel-chosen address, keep old alive during transition */
    uint8_t *l_new_base2 = mmap(NULL, a_new_size, PROT_READ | PROT_WRITE,
                                MAP_SHARED, a_cache->fd, 0);
    if (l_new_base2 == MAP_FAILED) {
        log_it(L_ERROR, "mmap fallback failed: %s", strerror(errno));
        return -1;
    }

    uint8_t *l_old_base = a_cache->base;
    uint64_t l_old_size = a_cache->mapped_size;

    a_cache->base = l_new_base2;
    a_cache->mapped_size = a_new_size;

    if (l_new_base2 != l_old_base)
        munmap(l_old_base, l_old_size);
    return 0;
}

uint64_t dap_ledger_cache_append(dap_ledger_cache_t *a_cache, const void *a_record, uint32_t a_record_size)
{
    if (!a_cache || !a_record || a_record_size < DAP_LEDGER_CACHE_RECORD_HDR_SIZE)
        return (uint64_t)-1;

    if (dap_ledger_cache_ensure_headroom(a_cache, a_record_size) != 0)
        return (uint64_t)-1;

    uint64_t l_offset = a_cache->data_end;
    memcpy(a_cache->base + l_offset, a_record, a_record_size);

    a_cache->data_end += a_record_size;
    a_cache->record_count++;

    /* Update header in mmap — always mark dirty so a crash leaves the flag set */
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)a_cache->base;
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;
    l_hdr->data_end = a_cache->data_end;
    l_hdr->record_count = a_cache->record_count;
    a_cache->dirty = true;

    return l_offset;
}

int dap_ledger_cache_validate_record(const uint8_t *a_base, uint64_t a_offset, uint64_t a_data_end)
{
    if (!a_base)
        return -1;

    /* Must fit at least record header */
    if (a_offset + DAP_LEDGER_CACHE_RECORD_HDR_SIZE > a_data_end)
        return -1;

    const dap_ledger_cache_record_hdr_t *l_hdr =
        (const dap_ledger_cache_record_hdr_t *)(a_base + a_offset);

    /* record_size must be at least 8 (the header itself); also prevents infinite loop if 0 */
    if (l_hdr->record_size < DAP_LEDGER_CACHE_RECORD_HDR_SIZE)
        return -2;

    /* Record must fit within data_end */
    if (a_offset + l_hdr->record_size > a_data_end)
        return -4;

    /* Validate record type and minimum size */
    uint32_t l_min_size = dap_ledger_cache_min_record_size(l_hdr->record_type);
    if (l_min_size > 0 && l_hdr->record_size < l_min_size)
        return -5;

    /* Unknown record types (> MAX) are allowed — skipped by callers using record_size */

    /* For TX records, cross-check n_outs against record_size to prevent OOB reads */
    if (l_hdr->record_type == DAP_LEDGER_CACHE_REC_TX) {
        const dap_ledger_cache_tx_record_t *l_tx =
            (const dap_ledger_cache_tx_record_t *)(a_base + a_offset);
        uint64_t l_expected_size = DAP_LEDGER_CACHE_TX_MIN_SIZE + (uint64_t)l_tx->n_outs * sizeof(dap_hash_fast_t);
        if (l_hdr->record_size < l_expected_size)
            return -6;
    }

    return 0;
}

int64_t dap_ledger_cache_scan(dap_ledger_cache_t *a_cache, dap_ledger_cache_scan_callback_t a_callback,
                              void *a_user_data, bool a_truncate_on_error)
{
    if (!a_cache || !a_cache->base)
        return -1;

    uint64_t l_offset = DAP_LEDGER_CACHE_HEADER_SIZE;
    int64_t l_count = 0;

    while (l_offset < a_cache->data_end) {
        int l_rc = dap_ledger_cache_validate_record(a_cache->base, l_offset, a_cache->data_end);
        if (l_rc != 0) {
            if (a_truncate_on_error) {
                log_it(L_WARNING, "Invalid record at offset %llu (error %d), truncating",
                       (unsigned long long)l_offset, l_rc);
                a_cache->data_end = l_offset;
                /* Update header */
                dap_ledger_cache_file_header_t *l_hdr =
                    (dap_ledger_cache_file_header_t *)a_cache->base;
                l_hdr->data_end = a_cache->data_end;
                l_hdr->record_count = (uint64_t)l_count;
                a_cache->record_count = (uint64_t)l_count;
            }
            break;
        }

        const dap_ledger_cache_record_hdr_t *l_rec_hdr =
            (const dap_ledger_cache_record_hdr_t *)(a_cache->base + l_offset);

        if (a_callback) {
            int l_cb_rc = a_callback(l_rec_hdr, l_offset, a_user_data);
            if (l_cb_rc != 0)
                break;
        }

        l_offset += l_rec_hdr->record_size;
        l_count++;
    }

    return l_count;
}

int dap_ledger_cache_shutdown(dap_ledger_cache_t *a_cache,
                              const dap_ledger_cache_manifest_entry_t *a_manifest_entries,
                              size_t a_manifest_count)
{
    if (!a_cache || !a_cache->base)
        return -1;

    /* Step 1: Write manifest section at data_end */
    size_t l_manifest_size = a_manifest_count * sizeof(dap_ledger_cache_manifest_entry_t);
    if (l_manifest_size > 0) {
        if (dap_ledger_cache_ensure_headroom(a_cache, l_manifest_size) != 0)
            return -1;
        memcpy(a_cache->base + a_cache->data_end, a_manifest_entries, l_manifest_size);
    }

    /* Step 2: Compute manifest_hash and write to header */
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)a_cache->base;
    if (l_manifest_size > 0) {
        dap_hash_fast(a_cache->base + a_cache->data_end, l_manifest_size,
                      (dap_hash_fast_t *)l_hdr->manifest_hash);
    } else {
        memset(l_hdr->manifest_hash, 0, 32);
    }

    /* Update header fields */
    l_hdr->data_end = a_cache->data_end;
    l_hdr->record_count = a_cache->record_count;
    l_hdr->manifest_count = (uint64_t)a_manifest_count;

    /* Step 3: msync full file — flush all data + manifest */
    if (msync(a_cache->base, a_cache->mapped_size, MS_SYNC) != 0) {
        log_it(L_ERROR, "msync full file failed: %s", strerror(errno));
        return -1;
    }

    /* Step 4: Set dirty_flag = CLEAN */
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_CLEAN;

    /* Step 5: msync header page only */
    long l_page_size = sysconf(_SC_PAGESIZE);
    if (l_page_size <= 0)
        l_page_size = 4096;
    if (msync(a_cache->base, (size_t)l_page_size, MS_SYNC) != 0) {
        log_it(L_ERROR, "msync header page failed: %s", strerror(errno));
        return -1;
    }

    /* Step 6: fdatasync */
    if (fdatasync(a_cache->fd) != 0) {
        log_it(L_ERROR, "fdatasync failed: %s", strerror(errno));
        return -1;
    }

    a_cache->dirty = false;

    /* Step 7 + 8: munmap + close */
    dap_ledger_cache_close(a_cache);

    return 0;
}

int dap_ledger_cache_validate_manifest(dap_ledger_cache_t *a_cache)
{
    if (!a_cache || !a_cache->base)
        return -1;

    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)a_cache->base;

    if (l_hdr->magic != DAP_LEDGER_CACHE_MAGIC)
        return -2;

    if (l_hdr->version != DAP_LEDGER_CACHE_VERSION)
        return -3;

    if (l_hdr->dirty_flag != DAP_LEDGER_CACHE_DIRTY_CLEAN)
        return -4;

    if (l_hdr->data_end > a_cache->mapped_size)
        return -5;

    if (l_hdr->data_end < DAP_LEDGER_CACHE_HEADER_SIZE)
        return -6;

    /* Validate manifest hash: manifest is at [data_end .. data_end + manifest_count * 56) */
    uint64_t l_manifest_count = l_hdr->manifest_count;
    size_t l_manifest_size = (size_t)(l_manifest_count * sizeof(dap_ledger_cache_manifest_entry_t));

    if (l_manifest_size > 0) {
        if (l_hdr->data_end + l_manifest_size > a_cache->mapped_size)
            return -7;

        dap_hash_fast_t l_computed_hash;
        dap_hash_fast(a_cache->base + l_hdr->data_end, l_manifest_size, &l_computed_hash);
        if (memcmp(&l_computed_hash, l_hdr->manifest_hash, sizeof(dap_hash_fast_t)) != 0)
            return -8;
    } else {
        /* No manifest entries: hash must be all zeros */
        uint8_t l_zero[32] = {0};
        if (memcmp(l_hdr->manifest_hash, l_zero, 32) != 0)
            return -9;
    }

    /* Validate record_count via quick scan */
    uint64_t l_offset = DAP_LEDGER_CACHE_HEADER_SIZE;
    uint64_t l_scan_count = 0;
    while (l_offset < l_hdr->data_end) {
        if (dap_ledger_cache_validate_record(a_cache->base, l_offset, l_hdr->data_end) != 0)
            return -10;
        const dap_ledger_cache_record_hdr_t *l_rec =
            (const dap_ledger_cache_record_hdr_t *)(a_cache->base + l_offset);
        l_offset += l_rec->record_size;
        l_scan_count++;
    }

    if (l_scan_count != l_hdr->record_count)
        return -11;

    return 0;
}

int dap_ledger_cache_compact(dap_ledger_cache_t *a_cache,
                             const dap_ledger_cache_manifest_entry_t *a_manifest_entries,
                             size_t a_manifest_count)
{
    if (!a_cache || !a_cache->base || !a_cache->file_path)
        return -1;

    /* Build temp path */
    size_t l_path_len = strlen(a_cache->file_path);
    char *l_tmp_path = malloc(l_path_len + 5);
    if (!l_tmp_path)
        return -1;
    snprintf(l_tmp_path, l_path_len + 5, "%s.tmp", a_cache->file_path);

    /* Create temp file */
    int l_tmp_fd = open(l_tmp_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (l_tmp_fd < 0) {
        log_it(L_ERROR, "compact: open(%s) failed: %s", l_tmp_path, strerror(errno));
        free(l_tmp_path);
        return -1;
    }

    /* Compute output size: scan live records */
    uint64_t l_live_data_size = DAP_LEDGER_CACHE_HEADER_SIZE;
    uint64_t l_live_count = 0;
    uint64_t l_offset = DAP_LEDGER_CACHE_HEADER_SIZE;
    while (l_offset < a_cache->data_end) {
        if (dap_ledger_cache_validate_record(a_cache->base, l_offset, a_cache->data_end) != 0)
            break;
        const dap_ledger_cache_record_hdr_t *l_rec =
            (const dap_ledger_cache_record_hdr_t *)(a_cache->base + l_offset);
        if (!dap_ledger_cache_record_is_tombstoned(a_cache->base, l_offset)) {
            l_live_data_size += l_rec->record_size;
            l_live_count++;
        }
        l_offset += l_rec->record_size;
    }

    size_t l_manifest_size = a_manifest_count * sizeof(dap_ledger_cache_manifest_entry_t);
    uint64_t l_file_size = l_live_data_size + l_manifest_size + DAP_LEDGER_CACHE_HEADROOM;

    if (ftruncate(l_tmp_fd, (off_t)l_file_size) != 0) {
        log_it(L_ERROR, "compact: ftruncate failed: %s", strerror(errno));
        close(l_tmp_fd);
        unlink(l_tmp_path);
        free(l_tmp_path);
        return -1;
    }

    uint8_t *l_tmp_base = mmap(NULL, l_file_size, PROT_READ | PROT_WRITE,
                                MAP_SHARED, l_tmp_fd, 0);
    if (l_tmp_base == MAP_FAILED) {
        log_it(L_ERROR, "compact: mmap failed: %s", strerror(errno));
        close(l_tmp_fd);
        unlink(l_tmp_path);
        free(l_tmp_path);
        return -1;
    }

    /* Write fresh header */
    dap_ledger_cache_file_header_t *l_new_hdr = (dap_ledger_cache_file_header_t *)l_tmp_base;
    memset(l_new_hdr, 0, sizeof(*l_new_hdr));
    l_new_hdr->magic = DAP_LEDGER_CACHE_MAGIC;
    l_new_hdr->version = DAP_LEDGER_CACHE_VERSION;
    l_new_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;
    l_new_hdr->net_id = ((dap_ledger_cache_file_header_t *)a_cache->base)->net_id;
    l_new_hdr->created_at = ((dap_ledger_cache_file_header_t *)a_cache->base)->created_at;

    /* Copy live records */
    uint64_t l_write_offset = DAP_LEDGER_CACHE_HEADER_SIZE;
    l_offset = DAP_LEDGER_CACHE_HEADER_SIZE;
    while (l_offset < a_cache->data_end) {
        if (dap_ledger_cache_validate_record(a_cache->base, l_offset, a_cache->data_end) != 0)
            break;
        const dap_ledger_cache_record_hdr_t *l_rec =
            (const dap_ledger_cache_record_hdr_t *)(a_cache->base + l_offset);
        if (!dap_ledger_cache_record_is_tombstoned(a_cache->base, l_offset)) {
            memcpy(l_tmp_base + l_write_offset, a_cache->base + l_offset, l_rec->record_size);
            l_write_offset += l_rec->record_size;
        }
        l_offset += l_rec->record_size;
    }

    l_new_hdr->data_end = l_write_offset;
    l_new_hdr->record_count = l_live_count;
    l_new_hdr->manifest_count = (uint64_t)a_manifest_count;

    /* Write manifest */
    if (l_manifest_size > 0) {
        memcpy(l_tmp_base + l_write_offset, a_manifest_entries, l_manifest_size);
        dap_hash_fast(l_tmp_base + l_write_offset, l_manifest_size,
                      (dap_hash_fast_t *)l_new_hdr->manifest_hash);
    } else {
        memset(l_new_hdr->manifest_hash, 0, 32);
    }

    /* msync full temp file */
    if (msync(l_tmp_base, l_file_size, MS_SYNC) != 0) {
        log_it(L_ERROR, "compact: msync temp failed: %s", strerror(errno));
        munmap(l_tmp_base, l_file_size);
        close(l_tmp_fd);
        unlink(l_tmp_path);
        free(l_tmp_path);
        return -1;
    }

    /* Set CLEAN and sync to disk */
    l_new_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_CLEAN;
    long l_page_size = sysconf(_SC_PAGESIZE);
    if (l_page_size <= 0)
        l_page_size = 4096;
    if (msync(l_tmp_base, (size_t)l_page_size, MS_SYNC) != 0 ||
        fdatasync(l_tmp_fd) != 0)
    {
        log_it(L_ERROR, "compact: failed to sync CLEAN header: %s", strerror(errno));
        munmap(l_tmp_base, l_file_size);
        close(l_tmp_fd);
        unlink(l_tmp_path);
        free(l_tmp_path);
        return -1;
    }

    munmap(l_tmp_base, l_file_size);
    close(l_tmp_fd);

    /* Atomic rename */
    char *l_orig_path = strdup(a_cache->file_path);
    dap_ledger_cache_close(a_cache);

    if (rename(l_tmp_path, l_orig_path) != 0) {
        log_it(L_ERROR, "compact: rename(%s, %s) failed: %s",
               l_tmp_path, l_orig_path, strerror(errno));
        free(l_tmp_path);
        free(l_orig_path);
        return -1;
    }

    /* fdatasync parent directory for rename durability */
    char *l_dir = strdup(l_orig_path);
    char *l_slash = strrchr(l_dir, '/');
    if (l_slash) {
        *l_slash = '\0';
        int l_dir_fd = open(l_dir, O_RDONLY);
        if (l_dir_fd >= 0) {
            fdatasync(l_dir_fd);
            close(l_dir_fd);
        }
    }
    free(l_dir);

    /* Reopen compacted file */
    int l_rc = dap_ledger_cache_open(a_cache, l_orig_path, 0);

    free(l_tmp_path);
    free(l_orig_path);
    return l_rc;
}

int dap_ledger_cache_purge(dap_ledger_cache_t *a_cache)
{
    if (!a_cache || !a_cache->base)
        return -1;

    a_cache->data_end = DAP_LEDGER_CACHE_HEADER_SIZE;
    a_cache->record_count = 0;

    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)a_cache->base;
    l_hdr->data_end = DAP_LEDGER_CACHE_HEADER_SIZE;
    l_hdr->record_count = 0;
    l_hdr->manifest_count = 0;
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;
    memset(l_hdr->manifest_hash, 0, 32);

    if (a_cache->mapped_size > DAP_LEDGER_CACHE_HEADER_SIZE)
        memset(a_cache->base + DAP_LEDGER_CACHE_HEADER_SIZE, 0,
               (size_t)(a_cache->mapped_size - DAP_LEDGER_CACHE_HEADER_SIZE));

    a_cache->dirty = true;

    long l_page_size = sysconf(_SC_PAGESIZE);
    if (l_page_size <= 0)
        l_page_size = 4096;
    msync(a_cache->base, (size_t)l_page_size, MS_SYNC);

    return 0;
}

/* ===========================================================================
 *  Higher-level record append helpers
 * =========================================================================== */

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
                                           const dap_hash_fast_t *a_out_spent_hashes)
{
    uint32_t l_rec_size = (uint32_t)(DAP_LEDGER_CACHE_TX_MIN_SIZE + a_n_outs * sizeof(dap_hash_fast_t));
    uint8_t *l_buf = calloc(1, l_rec_size);
    if (!l_buf)
        return (uint64_t)-1;

    dap_ledger_cache_tx_record_t *l_rec = (dap_ledger_cache_tx_record_t *)l_buf;
    l_rec->hdr.record_size = l_rec_size;
    l_rec->hdr.record_type = DAP_LEDGER_CACHE_REC_TX;
    l_rec->tx_hash_fast = *a_tx_hash;
    l_rec->ts_added = a_ts_added;
    l_rec->ts_created = a_ts_created;
    l_rec->n_outs = a_n_outs;
    l_rec->n_outs_used = a_n_outs_used;
    memcpy(l_rec->token_ticker, a_token_ticker, 10);
    l_rec->flags = a_flags;
    l_rec->tombstone = a_tombstone;
    l_rec->ts_spent = a_ts_spent;
    l_rec->tag = a_tag;
    l_rec->action = a_action;
    l_rec->datum_size = a_datum_size;
    l_rec->chain_id = a_chain_id;
    l_rec->cell_id = a_cell_id;
    l_rec->datum_file_offset = a_datum_file_offset;
    if (a_out_spent_hashes && a_n_outs > 0)
        memcpy(l_rec->out_spent_hashes, a_out_spent_hashes, a_n_outs * sizeof(dap_hash_fast_t));

    uint64_t l_offset = dap_ledger_cache_append(a_cache, l_buf, l_rec_size);
    free(l_buf);
    return l_offset;
}

uint64_t dap_ledger_cache_append_token_record(dap_ledger_cache_t *a_cache,
                                              const dap_hash_fast_t *a_token_hash,
                                              const char a_ticker[10],
                                              uint16_t a_subtype,
                                              const uint256_t *a_current_supply,
                                              uint64_t a_datum_size,
                                              uint64_t a_chain_id,
                                              uint64_t a_cell_id,
                                              uint64_t a_datum_file_offset)
{
    dap_ledger_cache_token_record_t l_rec = {0};
    l_rec.hdr.record_size = DAP_LEDGER_CACHE_TOKEN_SIZE;
    l_rec.hdr.record_type = DAP_LEDGER_CACHE_REC_TOKEN;
    l_rec.token_hash = *a_token_hash;
    memcpy(l_rec.ticker, a_ticker, 10);
    l_rec.subtype = a_subtype;
    l_rec.current_supply = *a_current_supply;
    l_rec.datum_size = a_datum_size;
    l_rec.chain_id = a_chain_id;
    l_rec.cell_id = a_cell_id;
    l_rec.datum_file_offset = a_datum_file_offset;
    return dap_ledger_cache_append(a_cache, &l_rec, sizeof(l_rec));
}

uint64_t dap_ledger_cache_append_emission_record(dap_ledger_cache_t *a_cache,
                                                 const dap_hash_fast_t *a_emission_hash,
                                                 const char a_ticker[10],
                                                 uint64_t a_ts_added,
                                                 uint64_t a_datum_size,
                                                 uint64_t a_chain_id,
                                                 uint64_t a_cell_id,
                                                 uint64_t a_datum_file_offset,
                                                 bool a_is_hardfork)
{
    dap_ledger_cache_emission_record_t l_rec = {0};
    l_rec.hdr.record_size = DAP_LEDGER_CACHE_EMISSION_SIZE;
    l_rec.hdr.record_type = DAP_LEDGER_CACHE_REC_EMISSION;
    l_rec.datum_token_emission_hash = *a_emission_hash;
    if (a_ticker)
        memcpy(l_rec.ticker, a_ticker, 10);
    l_rec.ts_added = a_ts_added;
    l_rec.datum_size = a_datum_size;
    l_rec.chain_id = a_chain_id;
    l_rec.cell_id = a_cell_id;
    l_rec.datum_file_offset = a_datum_file_offset;
    l_rec.is_hardfork = a_is_hardfork ? 1 : 0;
    return dap_ledger_cache_append(a_cache, &l_rec, sizeof(l_rec));
}

uint64_t dap_ledger_cache_append_stake_lock_record(dap_ledger_cache_t *a_cache,
                                                   const dap_hash_fast_t *a_stake_lock_hash,
                                                   uint64_t a_datum_file_offset)
{
    dap_ledger_cache_stake_lock_record_t l_rec = {0};
    l_rec.hdr.record_size = DAP_LEDGER_CACHE_STAKE_LOCK_SIZE;
    l_rec.hdr.record_type = DAP_LEDGER_CACHE_REC_STAKE_LOCK;
    l_rec.tx_for_stake_lock_hash = *a_stake_lock_hash;
    l_rec.datum_file_offset = a_datum_file_offset;
    return dap_ledger_cache_append(a_cache, &l_rec, sizeof(l_rec));
}

uint64_t dap_ledger_cache_append_token_update_record(dap_ledger_cache_t *a_cache,
                                                     const dap_hash_fast_t *a_update_hash,
                                                     const char a_ticker[10],
                                                     uint64_t a_datum_size,
                                                     uint64_t a_updated_time,
                                                     uint64_t a_chain_id,
                                                     uint64_t a_cell_id,
                                                     uint64_t a_datum_file_offset)
{
    dap_ledger_cache_token_update_record_t l_rec = {0};
    l_rec.hdr.record_size = DAP_LEDGER_CACHE_TOKEN_UPDATE_SIZE;
    l_rec.hdr.record_type = DAP_LEDGER_CACHE_REC_TOKEN_UPDATE;
    l_rec.update_token_hash = *a_update_hash;
    memcpy(l_rec.ticker, a_ticker, 10);
    l_rec.datum_size = a_datum_size;
    l_rec.updated_time = a_updated_time;
    l_rec.chain_id = a_chain_id;
    l_rec.cell_id = a_cell_id;
    l_rec.datum_file_offset = a_datum_file_offset;
    return dap_ledger_cache_append(a_cache, &l_rec, sizeof(l_rec));
}

/* ===========================================================================
 *  In-place mutable field updates
 * =========================================================================== */

int dap_ledger_cache_update_tx_spent(dap_ledger_cache_t *a_cache,
                                     uint64_t a_record_offset,
                                     uint32_t a_out_idx,
                                     const dap_hash_fast_t *a_spender_hash,
                                     uint32_t a_n_outs_used,
                                     uint64_t a_ts_spent)
{
    if (!a_cache || !a_cache->base)
        return -1;
    if (a_record_offset + DAP_LEDGER_CACHE_TX_MIN_SIZE > a_cache->data_end)
        return -1;

    dap_ledger_cache_tx_record_t *l_rec =
        (dap_ledger_cache_tx_record_t *)(a_cache->base + a_record_offset);
    if (l_rec->hdr.record_type != DAP_LEDGER_CACHE_REC_TX)
        return -2;
    if (a_out_idx >= l_rec->n_outs)
        return -3;
    if (a_n_outs_used > l_rec->n_outs)
        return -4;
    if (a_record_offset + l_rec->hdr.record_size > a_cache->data_end)
        return -1;

    l_rec->out_spent_hashes[a_out_idx] = *a_spender_hash;
    l_rec->n_outs_used = a_n_outs_used;
    l_rec->ts_spent = a_ts_spent;
    return 0;
}

int dap_ledger_cache_update_emission_spent(dap_ledger_cache_t *a_cache,
                                           uint64_t a_record_offset,
                                           const dap_hash_fast_t *a_tx_hash)
{
    if (!a_cache || !a_cache->base)
        return -1;
    if (a_record_offset + DAP_LEDGER_CACHE_EMISSION_SIZE > a_cache->data_end)
        return -1;

    dap_ledger_cache_emission_record_t *l_rec =
        (dap_ledger_cache_emission_record_t *)(a_cache->base + a_record_offset);
    if (l_rec->hdr.record_type != DAP_LEDGER_CACHE_REC_EMISSION)
        return -2;

    if (a_tx_hash)
        l_rec->tx_used_out = *a_tx_hash;
    else
        memset(&l_rec->tx_used_out, 0, sizeof(dap_hash_fast_t));
    return 0;
}

int dap_ledger_cache_update_stake_lock_spent(dap_ledger_cache_t *a_cache,
                                             uint64_t a_record_offset,
                                             const dap_hash_fast_t *a_tx_hash)
{
    if (!a_cache || !a_cache->base)
        return -1;
    if (a_record_offset + DAP_LEDGER_CACHE_STAKE_LOCK_SIZE > a_cache->data_end)
        return -1;

    dap_ledger_cache_stake_lock_record_t *l_rec =
        (dap_ledger_cache_stake_lock_record_t *)(a_cache->base + a_record_offset);
    if (l_rec->hdr.record_type != DAP_LEDGER_CACHE_REC_STAKE_LOCK)
        return -2;

    if (a_tx_hash)
        l_rec->tx_used_out = *a_tx_hash;
    else
        memset(&l_rec->tx_used_out, 0, sizeof(dap_hash_fast_t));
    return 0;
}

int dap_ledger_cache_update_token_supply(dap_ledger_cache_t *a_cache,
                                         uint64_t a_record_offset,
                                         const uint256_t *a_new_supply)
{
    if (!a_cache || !a_cache->base || !a_new_supply)
        return -1;
    if (a_record_offset + DAP_LEDGER_CACHE_TOKEN_SIZE > a_cache->data_end)
        return -1;

    dap_ledger_cache_token_record_t *l_rec =
        (dap_ledger_cache_token_record_t *)(a_cache->base + a_record_offset);
    if (l_rec->hdr.record_type != DAP_LEDGER_CACHE_REC_TOKEN)
        return -2;

    l_rec->current_supply = *a_new_supply;
    return 0;
}

int dap_ledger_cache_tombstone_tx(dap_ledger_cache_t *a_cache, uint64_t a_record_offset)
{
    if (!a_cache || !a_cache->base)
        return -1;
    if (a_record_offset + DAP_LEDGER_CACHE_TX_MIN_SIZE > a_cache->data_end)
        return -1;

    dap_ledger_cache_tx_record_t *l_rec =
        (dap_ledger_cache_tx_record_t *)(a_cache->base + a_record_offset);
    if (l_rec->hdr.record_type != DAP_LEDGER_CACHE_REC_TX)
        return -2;

    l_rec->tombstone = 1;
    return 0;
}

int dap_ledger_cache_warm_load(dap_ledger_cache_t *a_cache,
                               const dap_ledger_cache_warm_load_callbacks_t *a_callbacks)
{
    if (!a_cache || !a_cache->base || !a_callbacks)
        return -1;

    int l_manifest_rc = dap_ledger_cache_validate_manifest(a_cache);
    if (l_manifest_rc != 0) {
        log_it(L_WARNING, "warm_load: manifest validation failed (rc=%d)", l_manifest_rc);
        return -2;
    }

    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)a_cache->base;
    uint64_t l_offset = DAP_LEDGER_CACHE_HEADER_SIZE;
    int64_t l_count = 0;

    while (l_offset < l_hdr->data_end) {
        int l_rc = dap_ledger_cache_validate_record(a_cache->base, l_offset, l_hdr->data_end);
        if (l_rc != 0) {
            log_it(L_ERROR, "warm_load: corrupt record at offset %llu (rc=%d)",
                   (unsigned long long)l_offset, l_rc);
            return -4;
        }

        const dap_ledger_cache_record_hdr_t *l_rec_hdr =
            (const dap_ledger_cache_record_hdr_t *)(a_cache->base + l_offset);
        int l_cb_rc = 0;

        bool l_tombstoned = dap_ledger_cache_record_is_tombstoned(a_cache->base, l_offset);

        switch (l_rec_hdr->record_type) {
        case DAP_LEDGER_CACHE_REC_TOKEN:
            if (!l_tombstoned && a_callbacks->on_token)
                l_cb_rc = a_callbacks->on_token(
                    (const dap_ledger_cache_token_record_t *)(a_cache->base + l_offset),
                    l_offset, a_callbacks->user_data);
            break;
        case DAP_LEDGER_CACHE_REC_EMISSION:
            if (!l_tombstoned && a_callbacks->on_emission)
                l_cb_rc = a_callbacks->on_emission(
                    (const dap_ledger_cache_emission_record_t *)(a_cache->base + l_offset),
                    l_offset, a_callbacks->user_data);
            break;
        case DAP_LEDGER_CACHE_REC_STAKE_LOCK:
            if (a_callbacks->on_stake_lock)
                l_cb_rc = a_callbacks->on_stake_lock(
                    (const dap_ledger_cache_stake_lock_record_t *)(a_cache->base + l_offset),
                    l_offset, a_callbacks->user_data);
            break;
        case DAP_LEDGER_CACHE_REC_TX:
            if (!l_tombstoned && a_callbacks->on_tx)
                l_cb_rc = a_callbacks->on_tx(
                    (const dap_ledger_cache_tx_record_t *)(a_cache->base + l_offset),
                    l_offset, a_callbacks->user_data);
            break;
        case DAP_LEDGER_CACHE_REC_TOKEN_UPDATE:
            if (!l_tombstoned && a_callbacks->on_token_update)
                l_cb_rc = a_callbacks->on_token_update(
                    (const dap_ledger_cache_token_update_record_t *)(a_cache->base + l_offset),
                    l_offset, a_callbacks->user_data);
            break;
        default:
            break;
        }

        if (l_cb_rc != 0) {
            log_it(L_WARNING, "warm_load: callback aborted at offset %llu",
                   (unsigned long long)l_offset);
            return -3;
        }

        l_offset += l_rec_hdr->record_size;
        l_count++;
    }

    a_cache->record_count = (uint64_t)l_count;

    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;
    msync(a_cache->base, DAP_LEDGER_CACHE_HEADER_SIZE, MS_SYNC);

    log_it(L_INFO, "warm_load: loaded %lld records from cache", (long long)l_count);
    return 0;
}
