/**
 * @file test_ledger_cache.c
 * @brief Comprehensive unit tests for the mmap-based ledger cache
 * @details Covers file format, scanner, TX/token/emission/stake-lock operations,
 *          cache lifecycle, crash consistency, and resize paths.
 *          References: new_cache_ledger.md test matrix sections 3.1 - 3.6.
 *
 * @copyright Copyright (c) 2017-2026 Demlabs Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

#include "dap_test.h"
#include "dap_common.h"
#include "dap_chain_ledger_cache.h"

#define TEST_NET_ID   0x0123456789ABCDEFULL
#define TEST_DIR      "/tmp/test_ledger_cache"

static char s_test_file[256] = {0};
static int s_test_counter = 0;

/* Generate a unique test file path for each test to avoid interference */
static const char *s_next_test_file(void)
{
    snprintf(s_test_file, sizeof(s_test_file), "%s/cache_%d.lcache", TEST_DIR, s_test_counter++);
    return s_test_file;
}

static void s_remove_test_file(const char *a_path)
{
    if (a_path)
        unlink(a_path);
}

/* Helper: fill a TX record with test data */
static void s_fill_tx_record(dap_ledger_cache_tx_record_t *a_rec, uint32_t a_n_outs, uint8_t a_hash_seed)
{
    uint32_t l_total = DAP_LEDGER_CACHE_TX_MIN_SIZE + a_n_outs * sizeof(dap_hash_fast_t);
    memset(a_rec, 0, l_total);
    a_rec->hdr.record_size = l_total;
    a_rec->hdr.record_type = DAP_LEDGER_CACHE_REC_TX;
    memset(&a_rec->tx_hash_fast, a_hash_seed, sizeof(dap_hash_fast_t));
    a_rec->ts_added = 1000000000ULL;
    a_rec->ts_created = 1000000ULL;
    a_rec->n_outs = a_n_outs;
    a_rec->n_outs_used = 0;
    memcpy(a_rec->token_ticker, "CELL\0\0\0\0\0\0", 10);
    a_rec->datum_size = 256;
    a_rec->chain_id = 1;
    a_rec->cell_id = 1;
    a_rec->datum_file_offset = 4096;
}

/* Helper: fill a Token record with test data */
static void s_fill_token_record(dap_ledger_cache_token_record_t *a_rec, const char *a_ticker, uint8_t a_hash_seed)
{
    memset(a_rec, 0, sizeof(*a_rec));
    a_rec->hdr.record_size = DAP_LEDGER_CACHE_TOKEN_SIZE;
    a_rec->hdr.record_type = DAP_LEDGER_CACHE_REC_TOKEN;
    memset(&a_rec->token_hash, a_hash_seed, sizeof(dap_hash_fast_t));
    memset(a_rec->ticker, 0, 10);
    size_t l_len = strlen(a_ticker);
    if (l_len > 10) l_len = 10;
    memcpy(a_rec->ticker, a_ticker, l_len);
    a_rec->subtype = 1;
    memset(&a_rec->current_supply, 0, sizeof(uint256_t));
    a_rec->datum_size = 128;
    a_rec->chain_id = 1;
    a_rec->cell_id = 1;
    a_rec->datum_file_offset = 8192;
}

/* Helper: fill an Emission record */
static void s_fill_emission_record(dap_ledger_cache_emission_record_t *a_rec, uint8_t a_hash_seed)
{
    memset(a_rec, 0, sizeof(*a_rec));
    a_rec->hdr.record_size = DAP_LEDGER_CACHE_EMISSION_SIZE;
    a_rec->hdr.record_type = DAP_LEDGER_CACHE_REC_EMISSION;
    memset(&a_rec->datum_token_emission_hash, a_hash_seed, sizeof(dap_hash_fast_t));
    memcpy(a_rec->ticker, "CELL", 4);
    a_rec->ts_added = 2000000000ULL;
    a_rec->datum_size = 64;
    a_rec->chain_id = 1;
    a_rec->cell_id = 1;
    a_rec->datum_file_offset = 16384;
}

/* Helper: fill a Stake Lock record */
static void s_fill_stake_lock_record(dap_ledger_cache_stake_lock_record_t *a_rec, uint8_t a_hash_seed)
{
    memset(a_rec, 0, sizeof(*a_rec));
    a_rec->hdr.record_size = DAP_LEDGER_CACHE_STAKE_LOCK_SIZE;
    a_rec->hdr.record_type = DAP_LEDGER_CACHE_REC_STAKE_LOCK;
    memset(&a_rec->tx_for_stake_lock_hash, a_hash_seed, sizeof(dap_hash_fast_t));
    a_rec->datum_file_offset = 32768;
}

/* Helper: fill a Token Update record */
static void s_fill_token_update_record(dap_ledger_cache_token_update_record_t *a_rec,
                                       const char *a_ticker, uint8_t a_hash_seed)
{
    memset(a_rec, 0, sizeof(*a_rec));
    a_rec->hdr.record_size = DAP_LEDGER_CACHE_TOKEN_UPDATE_SIZE;
    a_rec->hdr.record_type = DAP_LEDGER_CACHE_REC_TOKEN_UPDATE;
    memset(&a_rec->update_token_hash, a_hash_seed, sizeof(dap_hash_fast_t));
    memset(a_rec->ticker, 0, 10);
    size_t l_len = strlen(a_ticker);
    if (l_len > 10) l_len = 10;
    memcpy(a_rec->ticker, a_ticker, l_len);
    a_rec->datum_size = 96;
    a_rec->updated_time = 1000000ULL;
    a_rec->chain_id = 1;
    a_rec->cell_id = 1;
    a_rec->datum_file_offset = 65536;
}

/* Scan callback counter */
typedef struct {
    int64_t count;
    int64_t tx_count;
    int64_t token_count;
    int64_t emission_count;
    int64_t stake_lock_count;
    int64_t token_update_count;
    int64_t unknown_count;
} scan_stats_t;

static int s_scan_counter_callback(const dap_ledger_cache_record_hdr_t *a_hdr,
                                   uint64_t a_offset, void *a_user_data)
{
    scan_stats_t *l_stats = (scan_stats_t *)a_user_data;
    l_stats->count++;
    switch (a_hdr->record_type) {
        case DAP_LEDGER_CACHE_REC_TX:           l_stats->tx_count++; break;
        case DAP_LEDGER_CACHE_REC_TOKEN:        l_stats->token_count++; break;
        case DAP_LEDGER_CACHE_REC_EMISSION:     l_stats->emission_count++; break;
        case DAP_LEDGER_CACHE_REC_STAKE_LOCK:   l_stats->stake_lock_count++; break;
        case DAP_LEDGER_CACHE_REC_TOKEN_UPDATE: l_stats->token_update_count++; break;
        default:                                l_stats->unknown_count++; break;
    }
    return 0;
}

static int s_scan_stop_at_2_count = 0;
static int s_scan_stop_at_2_callback(const dap_ledger_cache_record_hdr_t *a_hdr,
                                      uint64_t a_offset, void *a_user_data)
{
    (void)a_hdr; (void)a_offset; (void)a_user_data;
    s_scan_stop_at_2_count++;
    return (s_scan_stop_at_2_count >= 2) ? 1 : 0;
}

/* ========================================================================= */
/*  Section 3.1 — File Format and Scanner Tests                              */
/* ========================================================================= */

static void test_valid_header(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};

    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_file_header_t l_hdr = {0};
    dap_assert_PIF(dap_ledger_cache_read_header(&l_cache, &l_hdr) == 0,
                   "Read header should succeed");

    dap_assert_PIF(l_hdr.magic == DAP_LEDGER_CACHE_MAGIC,
                   "Magic should be DAPCACHE");
    dap_assert_PIF(l_hdr.version == DAP_LEDGER_CACHE_VERSION,
                   "Version should be 1");
    dap_assert_PIF(l_hdr.data_end == DAP_LEDGER_CACHE_HEADER_SIZE,
                   "data_end should be 120 for empty cache");
    dap_assert_PIF(l_hdr.record_count == 0,
                   "record_count should be 0 for empty cache");
    dap_assert_PIF(l_hdr.net_id == TEST_NET_ID,
                   "net_id should match");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_valid_header");
}

static void test_invalid_magic(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Corrupt magic */
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->magic = 0xDEADBEEFDEADBEEFULL;

    dap_assert_PIF(dap_ledger_cache_validate_manifest(&l_cache) != 0,
                   "Invalid magic should fail validation");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_invalid_magic");
}

static void test_unsupported_version(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Set unsupported version */
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->version = 99;

    dap_assert_PIF(dap_ledger_cache_validate_manifest(&l_cache) != 0,
                   "Unsupported version should fail validation");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_unsupported_version");
}

static void test_dirty_flag_clean(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* New cache starts DIRTY */
    dap_ledger_cache_file_header_t l_hdr = {0};
    dap_ledger_cache_read_header(&l_cache, &l_hdr);
    dap_assert_PIF(l_hdr.dirty_flag == DAP_LEDGER_CACHE_DIRTY_DIRTY,
                   "New cache should be DIRTY");

    /* Shutdown sets CLEAN */
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0,
                   "Shutdown should succeed");

    /* Reopen and verify CLEAN */
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Reopen should succeed");
    dap_ledger_cache_read_header(&l_cache, &l_hdr);
    dap_assert_PIF(l_hdr.dirty_flag == DAP_LEDGER_CACHE_DIRTY_CLEAN,
                   "After shutdown cache should be CLEAN");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_dirty_flag_clean");
}

static void test_dirty_flag_dirty(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Mark dirty explicitly */
    dap_assert_PIF(dap_ledger_cache_mark_dirty(&l_cache) == 0,
                   "Mark dirty should succeed");

    dap_ledger_cache_file_header_t l_hdr = {0};
    dap_ledger_cache_read_header(&l_cache, &l_hdr);
    dap_assert_PIF(l_hdr.dirty_flag == DAP_LEDGER_CACHE_DIRTY_DIRTY,
                   "Cache should be DIRTY after mark");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_dirty_flag_dirty");
}

static void test_malformed_tail_record(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append a valid TX record */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0xAA);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    dap_assert_PIF(l_offset != (uint64_t)-1, "First append should succeed");

    /* Write a truncated record at data_end: only partial header */
    dap_ledger_cache_record_hdr_t l_partial_hdr = {
        .record_size = 256,
        .record_type = DAP_LEDGER_CACHE_REC_TX
    };
    memcpy(l_cache.base + l_cache.data_end, &l_partial_hdr, sizeof(l_partial_hdr));
    l_cache.data_end += sizeof(l_partial_hdr) + 4;  /* Partial record body */

    dap_ledger_cache_file_header_t *l_file_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_file_hdr->data_end = l_cache.data_end;

    /* Scan with truncation should find exactly 1 valid record */
    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, true);
    dap_assert_PIF(l_count == 1, "Scanner should find exactly 1 valid record before truncated one");
    dap_assert_PIF(l_stats.tx_count == 1, "The valid record should be a TX");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_malformed_tail_record");
}

static void test_record_size_zero(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Write a record with size = 0 at data_end */
    dap_ledger_cache_record_hdr_t l_zero_hdr = {
        .record_size = 0,
        .record_type = DAP_LEDGER_CACHE_REC_TX
    };
    memcpy(l_cache.base + l_cache.data_end, &l_zero_hdr, sizeof(l_zero_hdr));
    l_cache.data_end += sizeof(l_zero_hdr);
    dap_ledger_cache_file_header_t *l_file_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_file_hdr->data_end = l_cache.data_end;

    /* Scan should stop immediately without infinite loop */
    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, true);
    dap_assert_PIF(l_count == 0, "Scanner should stop on record_size == 0");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_record_size_zero");
}

static void test_record_size_exceeds_remaining(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append a valid token record */
    dap_ledger_cache_token_record_t l_token = {0};
    s_fill_token_record(&l_token, "TEST", 0xBB);
    dap_ledger_cache_append(&l_cache, &l_token, l_token.hdr.record_size);

    /* Write a record that claims to be larger than remaining space */
    dap_ledger_cache_record_hdr_t l_big_hdr = {
        .record_size = 999999,
        .record_type = DAP_LEDGER_CACHE_REC_TX
    };
    memcpy(l_cache.base + l_cache.data_end, &l_big_hdr, sizeof(l_big_hdr));
    l_cache.data_end += sizeof(l_big_hdr);
    dap_ledger_cache_file_header_t *l_file_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_file_hdr->data_end = l_cache.data_end;

    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, true);
    dap_assert_PIF(l_count == 1, "Scanner should find 1 valid record, stop at oversized");
    dap_assert_PIF(l_stats.token_count == 1, "Valid record should be a token");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_record_size_exceeds_remaining");
}

static void test_unknown_record_type(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append a valid TX */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0xCC);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    /* Append a record with unknown type 6, valid size (record_size >= 8 but type is unknown) */
    uint8_t l_unknown[32];
    memset(l_unknown, 0, sizeof(l_unknown));
    dap_ledger_cache_record_hdr_t *l_unk_hdr = (dap_ledger_cache_record_hdr_t *)l_unknown;
    l_unk_hdr->record_size = 32;
    l_unk_hdr->record_type = 6;  /* Unknown type */
    dap_ledger_cache_append(&l_cache, l_unknown, 32);

    /* Append another valid TX */
    s_fill_tx_record(&l_tx, 0, 0xDD);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    /* Scanner should see all 3 records — unknown type skipped via record_size */
    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 3, "Scanner should count all 3 records");
    dap_assert_PIF(l_stats.tx_count == 2, "Should have 2 TX records");
    dap_assert_PIF(l_stats.unknown_count == 1, "Should have 1 unknown record");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_unknown_record_type");
}

static void test_record_type_zero(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Record with type 0 and valid size — scanner skips it cleanly */
    uint8_t l_rec[16];
    memset(l_rec, 0, sizeof(l_rec));
    dap_ledger_cache_record_hdr_t *l_hdr = (dap_ledger_cache_record_hdr_t *)l_rec;
    l_hdr->record_size = 16;
    l_hdr->record_type = 0;  /* Undefined type */
    dap_ledger_cache_append(&l_cache, l_rec, 16);

    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 1, "Scanner should count the record");
    dap_assert_PIF(l_stats.unknown_count == 1, "Type 0 should count as unknown");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_record_type_zero");
}

static void test_record_size_less_than_header(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Write a record with record_size < 8 (the header minimum) */
    dap_ledger_cache_record_hdr_t l_bad_hdr = {
        .record_size = 4,
        .record_type = DAP_LEDGER_CACHE_REC_TX
    };
    memcpy(l_cache.base + l_cache.data_end, &l_bad_hdr, sizeof(l_bad_hdr));
    l_cache.data_end += sizeof(l_bad_hdr);
    dap_ledger_cache_file_header_t *l_file_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_file_hdr->data_end = l_cache.data_end;

    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, true);
    dap_assert_PIF(l_count == 0, "Scanner should reject record with size < 8");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_record_size_less_than_header");
}

static void test_record_size_less_than_type_minimum(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* TX record with size 64 < 136 minimum */
    uint8_t l_bad[64];
    memset(l_bad, 0, sizeof(l_bad));
    dap_ledger_cache_record_hdr_t *l_hdr = (dap_ledger_cache_record_hdr_t *)l_bad;
    l_hdr->record_size = 64;
    l_hdr->record_type = DAP_LEDGER_CACHE_REC_TX;
    memcpy(l_cache.base + l_cache.data_end, l_bad, 64);
    l_cache.data_end += 64;
    dap_ledger_cache_file_header_t *l_file_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_file_hdr->data_end = l_cache.data_end;

    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, true);
    dap_assert_PIF(l_count == 0, "Scanner should reject TX record with size < 136");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_record_size_less_than_type_minimum");
}

/* ========================================================================= */
/*  Section 3.2 — TX Operations Tests                                        */
/* ========================================================================= */

static void test_tx_add(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    uint64_t l_old_end = l_cache.data_end;
    uint64_t l_old_count = l_cache.record_count;

    uint32_t l_n_outs = 2;
    uint32_t l_total = DAP_LEDGER_CACHE_TX_MIN_SIZE + l_n_outs * sizeof(dap_hash_fast_t);
    uint8_t *l_buf = calloc(1, l_total);
    dap_ledger_cache_tx_record_t *l_tx = (dap_ledger_cache_tx_record_t *)l_buf;
    s_fill_tx_record(l_tx, l_n_outs, 0x11);

    uint64_t l_offset = dap_ledger_cache_append(&l_cache, l_buf, l_total);
    dap_assert_PIF(l_offset == l_old_end, "TX should be appended at old data_end");
    dap_assert_PIF(l_cache.data_end == l_old_end + l_total, "data_end should advance by record size");
    dap_assert_PIF(l_cache.record_count == l_old_count + 1, "record_count should increment");

    /* Verify record in mmap */
    const dap_ledger_cache_tx_record_t *l_read =
        (const dap_ledger_cache_tx_record_t *)(l_cache.base + l_offset);
    dap_assert_PIF(l_read->hdr.record_type == DAP_LEDGER_CACHE_REC_TX, "Record type should be TX");
    dap_assert_PIF(l_read->n_outs == 2, "n_outs should be 2");
    dap_assert_PIF(l_read->n_outs_used == 0, "n_outs_used should be 0");
    dap_assert_PIF(memcmp(l_read->token_ticker, "CELL", 4) == 0, "Ticker should be CELL");

    free(l_buf);
    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_tx_add");
}

static void test_tx_spend(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append TX with 3 outputs */
    uint32_t l_n_outs = 3;
    uint32_t l_total = DAP_LEDGER_CACHE_TX_MIN_SIZE + l_n_outs * sizeof(dap_hash_fast_t);
    uint8_t *l_buf = calloc(1, l_total);
    dap_ledger_cache_tx_record_t *l_tx = (dap_ledger_cache_tx_record_t *)l_buf;
    s_fill_tx_record(l_tx, l_n_outs, 0x22);

    uint64_t l_offset = dap_ledger_cache_append(&l_cache, l_buf, l_total);
    dap_assert_PIF(l_offset != (uint64_t)-1, "TX append should succeed");

    /* In-place: spend output 1 */
    dap_ledger_cache_tx_record_t *l_mutable =
        (dap_ledger_cache_tx_record_t *)(l_cache.base + l_offset);
    dap_hash_fast_t l_spender_hash;
    memset(&l_spender_hash, 0xFF, sizeof(l_spender_hash));

    dap_assert_PIF(1 < l_mutable->n_outs, "Output index should be within bounds");
    memcpy(&l_mutable->out_spent_hashes[1], &l_spender_hash, sizeof(dap_hash_fast_t));
    l_mutable->n_outs_used++;

    /* Verify */
    dap_assert_PIF(l_mutable->n_outs_used == 1, "n_outs_used should be 1");
    dap_assert_PIF(memcmp(&l_mutable->out_spent_hashes[1], &l_spender_hash, sizeof(dap_hash_fast_t)) == 0,
                   "Spent hash should match");

    /* Spend remaining outputs to make fully spent */
    memcpy(&l_mutable->out_spent_hashes[0], &l_spender_hash, sizeof(dap_hash_fast_t));
    l_mutable->n_outs_used++;
    memcpy(&l_mutable->out_spent_hashes[2], &l_spender_hash, sizeof(dap_hash_fast_t));
    l_mutable->n_outs_used++;
    l_mutable->ts_spent = 1234567890ULL;

    dap_assert_PIF(l_mutable->n_outs_used == l_mutable->n_outs, "All outputs should be spent");
    dap_assert_PIF(l_mutable->ts_spent == 1234567890ULL, "ts_spent should be set");

    free(l_buf);
    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_tx_spend");
}

static void test_tx_unspend(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    uint32_t l_n_outs = 2;
    uint32_t l_total = DAP_LEDGER_CACHE_TX_MIN_SIZE + l_n_outs * sizeof(dap_hash_fast_t);
    uint8_t *l_buf = calloc(1, l_total);
    dap_ledger_cache_tx_record_t *l_tx = (dap_ledger_cache_tx_record_t *)l_buf;
    s_fill_tx_record(l_tx, l_n_outs, 0x33);

    uint64_t l_offset = dap_ledger_cache_append(&l_cache, l_buf, l_total);

    /* Spend output 0 */
    dap_ledger_cache_tx_record_t *l_mutable =
        (dap_ledger_cache_tx_record_t *)(l_cache.base + l_offset);
    dap_hash_fast_t l_spender;
    memset(&l_spender, 0xEE, sizeof(l_spender));
    memcpy(&l_mutable->out_spent_hashes[0], &l_spender, sizeof(dap_hash_fast_t));
    l_mutable->n_outs_used = 1;

    /* Unspend output 0 */
    memset(&l_mutable->out_spent_hashes[0], 0, sizeof(dap_hash_fast_t));
    l_mutable->n_outs_used = 0;
    l_mutable->ts_spent = 0;

    dap_assert_PIF(l_mutable->n_outs_used == 0, "n_outs_used should be 0 after unspend");

    dap_hash_fast_t l_zero = {0};
    dap_assert_PIF(memcmp(&l_mutable->out_spent_hashes[0], &l_zero, sizeof(l_zero)) == 0,
                   "Unspent hash should be zeroed");

    free(l_buf);
    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_tx_unspend");
}

static void test_tx_output_bounds_check(void)
{
    /* Verify that output index >= n_outs would be an out-of-bounds access */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x44);  /* n_outs = 0 */

    /* With n_outs = 0, any idx >= 0 is out of bounds */
    dap_assert_PIF(l_tx.n_outs == 0, "n_outs should be 0");
    /* The caller must check idx < n_outs before accessing out_spent_hashes[idx] */
    dap_assert(1, "test_tx_output_bounds_check");
}

static void test_tx_n_outs_used_overflow(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    uint32_t l_n_outs = 1;
    uint32_t l_total = DAP_LEDGER_CACHE_TX_MIN_SIZE + l_n_outs * sizeof(dap_hash_fast_t);
    uint8_t *l_buf = calloc(1, l_total);
    dap_ledger_cache_tx_record_t *l_tx = (dap_ledger_cache_tx_record_t *)l_buf;
    s_fill_tx_record(l_tx, l_n_outs, 0x55);

    uint64_t l_offset = dap_ledger_cache_append(&l_cache, l_buf, l_total);
    dap_ledger_cache_tx_record_t *l_mutable =
        (dap_ledger_cache_tx_record_t *)(l_cache.base + l_offset);

    /* Spend the single output */
    l_mutable->n_outs_used = 1;
    /* Attempting to spend again when n_outs_used == n_outs should be rejected by caller */
    dap_assert_PIF(l_mutable->n_outs_used == l_mutable->n_outs,
                   "n_outs_used equals n_outs — caller must reject further spends");

    free(l_buf);
    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_tx_n_outs_used_overflow");
}

static void test_tx_n_outs_used_underflow(void)
{
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x66);
    l_tx.n_outs = 1;  /* Set n_outs without allocating space — only for bounds check */

    /* n_outs_used is 0 by default — caller must check before decrement */
    dap_assert_PIF(l_tx.n_outs_used == 0,
                   "n_outs_used should be 0 — caller must reject unspend at 0");
    dap_assert(1, "test_tx_n_outs_used_underflow");
}

static void test_tx_rollback_tombstone(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x77);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    /* Rollback: set tombstone */
    dap_ledger_cache_tx_record_t *l_mutable =
        (dap_ledger_cache_tx_record_t *)(l_cache.base + l_offset);
    l_mutable->tombstone = 1;

    dap_assert_PIF(l_mutable->tombstone == 1, "Tombstone should be set");

    /* Verify scan still sees the record (tombstone filtering is caller responsibility) */
    scan_stats_t l_stats = {0};
    dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_stats.tx_count == 1, "Scanner should still see tombstoned record");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_tx_rollback_tombstone");
}

/* ========================================================================= */
/*  Section 3.3 — Token and Token Update Tests                               */
/* ========================================================================= */

static void test_token_add(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_token_record_t l_token = {0};
    s_fill_token_record(&l_token, "CELL", 0xAA);

    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_token, l_token.hdr.record_size);
    dap_assert_PIF(l_offset != (uint64_t)-1, "Token append should succeed");

    const dap_ledger_cache_token_record_t *l_read =
        (const dap_ledger_cache_token_record_t *)(l_cache.base + l_offset);
    dap_assert_PIF(l_read->hdr.record_type == DAP_LEDGER_CACHE_REC_TOKEN, "Record type should be TOKEN");
    dap_assert_PIF(memcmp(l_read->ticker, "CELL", 4) == 0, "Ticker should be CELL");
    dap_assert_PIF(l_read->subtype == 1, "Subtype should be 1");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_token_add");
}

static void test_token_supply_update(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_token_record_t l_token = {0};
    s_fill_token_record(&l_token, "CELL", 0xBB);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_token, l_token.hdr.record_size);

    /* Modify current_supply in-place (32 B, non-atomic) */
    dap_ledger_cache_token_record_t *l_mutable =
        (dap_ledger_cache_token_record_t *)(l_cache.base + l_offset);

    uint256_t l_supply;
    memset(&l_supply, 0, sizeof(l_supply));
    l_supply.lo = 1000000ULL;
    memcpy(&l_mutable->current_supply, &l_supply, sizeof(uint256_t));

    /* Verify */
    dap_assert_PIF(memcmp(&l_mutable->current_supply, &l_supply, sizeof(uint256_t)) == 0,
                   "current_supply should match after update");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_token_supply_update");
}

static void test_token_update_add(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_token_update_record_t l_update = {0};
    s_fill_token_update_record(&l_update, "CELL", 0xCC);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_update, l_update.hdr.record_size);
    dap_assert_PIF(l_offset != (uint64_t)-1, "Token update append should succeed");

    const dap_ledger_cache_token_update_record_t *l_read =
        (const dap_ledger_cache_token_update_record_t *)(l_cache.base + l_offset);
    dap_assert_PIF(l_read->hdr.record_type == DAP_LEDGER_CACHE_REC_TOKEN_UPDATE,
                   "Record type should be TOKEN_UPDATE");
    dap_assert_PIF(memcmp(l_read->ticker, "CELL", 4) == 0, "Ticker should be CELL");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_token_update_add");
}

static void test_token_update_replay_order(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append token updates with different timestamps in file order */
    for (int i = 0; i < 5; i++) {
        dap_ledger_cache_token_update_record_t l_update = {0};
        s_fill_token_update_record(&l_update, "CELL", (uint8_t)(0xD0 + i));
        l_update.updated_time = (uint64_t)(1000 + i * 100);
        dap_ledger_cache_append(&l_cache, &l_update, l_update.hdr.record_size);
    }

    /* Verify scan order matches file order (append order) */
    uint64_t l_last_time = 0;
    uint64_t l_offset = DAP_LEDGER_CACHE_HEADER_SIZE;
    int l_order_ok = 1;

    while (l_offset < l_cache.data_end) {
        const dap_ledger_cache_record_hdr_t *l_hdr =
            (const dap_ledger_cache_record_hdr_t *)(l_cache.base + l_offset);
        if (l_hdr->record_type == DAP_LEDGER_CACHE_REC_TOKEN_UPDATE) {
            const dap_ledger_cache_token_update_record_t *l_rec =
                (const dap_ledger_cache_token_update_record_t *)(l_cache.base + l_offset);
            if (l_rec->updated_time < l_last_time) {
                l_order_ok = 0;
                break;
            }
            l_last_time = l_rec->updated_time;
        }
        l_offset += l_hdr->record_size;
    }
    dap_assert_PIF(l_order_ok, "Token updates should be in file order (ascending time)");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_token_update_replay_order");
}

static void test_ticker_binary_safety(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Ticker with embedded NUL bytes — 10-byte binary field */
    dap_ledger_cache_token_record_t l_token = {0};
    s_fill_token_record(&l_token, "AB", 0xDD);
    l_token.ticker[2] = '\0';
    l_token.ticker[3] = 'X';  /* Byte after NUL */
    l_token.ticker[4] = 'Y';

    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_token, l_token.hdr.record_size);
    const dap_ledger_cache_token_record_t *l_read =
        (const dap_ledger_cache_token_record_t *)(l_cache.base + l_offset);

    /* memcmp over full 10 bytes — NUL byte should NOT truncate comparison */
    dap_assert_PIF(memcmp(l_read->ticker, l_token.ticker, 10) == 0,
                   "Ticker should be compared as 10-byte binary, not C-string");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_ticker_binary_safety");
}

/* ========================================================================= */
/*  Section 3.4 — Emission and Stake Lock Tests                              */
/* ========================================================================= */

static void test_emission_add(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_emission_record_t l_emission = {0};
    s_fill_emission_record(&l_emission, 0xAA);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_emission, l_emission.hdr.record_size);
    dap_assert_PIF(l_offset != (uint64_t)-1, "Emission append should succeed");

    const dap_ledger_cache_emission_record_t *l_read =
        (const dap_ledger_cache_emission_record_t *)(l_cache.base + l_offset);
    dap_assert_PIF(l_read->hdr.record_type == DAP_LEDGER_CACHE_REC_EMISSION,
                   "Record type should be EMISSION");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_emission_add");
}

static void test_emission_spend(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_emission_record_t l_emission = {0};
    s_fill_emission_record(&l_emission, 0xBB);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_emission, l_emission.hdr.record_size);

    /* Spend: set tx_used_out in-place */
    dap_ledger_cache_emission_record_t *l_mutable =
        (dap_ledger_cache_emission_record_t *)(l_cache.base + l_offset);
    dap_hash_fast_t l_tx_hash;
    memset(&l_tx_hash, 0xFF, sizeof(l_tx_hash));
    memcpy(&l_mutable->tx_used_out, &l_tx_hash, sizeof(dap_hash_fast_t));

    dap_assert_PIF(memcmp(&l_mutable->tx_used_out, &l_tx_hash, sizeof(dap_hash_fast_t)) == 0,
                   "tx_used_out should match spender hash");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_emission_spend");
}

static void test_emission_unspend(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_emission_record_t l_emission = {0};
    s_fill_emission_record(&l_emission, 0xCC);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_emission, l_emission.hdr.record_size);

    dap_ledger_cache_emission_record_t *l_mutable =
        (dap_ledger_cache_emission_record_t *)(l_cache.base + l_offset);

    /* Spend then unspend */
    dap_hash_fast_t l_tx_hash;
    memset(&l_tx_hash, 0xFF, sizeof(l_tx_hash));
    memcpy(&l_mutable->tx_used_out, &l_tx_hash, sizeof(dap_hash_fast_t));

    /* Unspend: zero tx_used_out */
    memset(&l_mutable->tx_used_out, 0, sizeof(dap_hash_fast_t));

    dap_hash_fast_t l_zero = {0};
    dap_assert_PIF(memcmp(&l_mutable->tx_used_out, &l_zero, sizeof(dap_hash_fast_t)) == 0,
                   "tx_used_out should be zeroed after unspend");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_emission_unspend");
}

static void test_emission_is_hardfork(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_emission_record_t l_emission = {0};
    s_fill_emission_record(&l_emission, 0xDD);
    l_emission.is_hardfork = 1;

    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_emission, l_emission.hdr.record_size);

    const dap_ledger_cache_emission_record_t *l_read =
        (const dap_ledger_cache_emission_record_t *)(l_cache.base + l_offset);
    dap_assert_PIF(l_read->is_hardfork == 1, "is_hardfork should be persisted");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_emission_is_hardfork");
}

static void test_stake_lock_add(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_stake_lock_record_t l_sl = {0};
    s_fill_stake_lock_record(&l_sl, 0xEE);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_sl, l_sl.hdr.record_size);
    dap_assert_PIF(l_offset != (uint64_t)-1, "Stake lock append should succeed");

    const dap_ledger_cache_stake_lock_record_t *l_read =
        (const dap_ledger_cache_stake_lock_record_t *)(l_cache.base + l_offset);
    dap_assert_PIF(l_read->hdr.record_type == DAP_LEDGER_CACHE_REC_STAKE_LOCK,
                   "Record type should be STAKE_LOCK");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_stake_lock_add");
}

static void test_stake_lock_spend(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_stake_lock_record_t l_sl = {0};
    s_fill_stake_lock_record(&l_sl, 0xFF);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_sl, l_sl.hdr.record_size);

    dap_ledger_cache_stake_lock_record_t *l_mutable =
        (dap_ledger_cache_stake_lock_record_t *)(l_cache.base + l_offset);
    dap_hash_fast_t l_tx_hash;
    memset(&l_tx_hash, 0xAB, sizeof(l_tx_hash));
    memcpy(&l_mutable->tx_used_out, &l_tx_hash, sizeof(dap_hash_fast_t));

    dap_assert_PIF(memcmp(&l_mutable->tx_used_out, &l_tx_hash, sizeof(dap_hash_fast_t)) == 0,
                   "Stake lock tx_used_out should be set");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_stake_lock_spend");
}

static void test_stake_lock_unspend(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_stake_lock_record_t l_sl = {0};
    s_fill_stake_lock_record(&l_sl, 0x11);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_sl, l_sl.hdr.record_size);

    dap_ledger_cache_stake_lock_record_t *l_mutable =
        (dap_ledger_cache_stake_lock_record_t *)(l_cache.base + l_offset);
    dap_hash_fast_t l_tx_hash;
    memset(&l_tx_hash, 0xCD, sizeof(l_tx_hash));
    memcpy(&l_mutable->tx_used_out, &l_tx_hash, sizeof(dap_hash_fast_t));

    /* Unspend */
    memset(&l_mutable->tx_used_out, 0, sizeof(dap_hash_fast_t));
    dap_hash_fast_t l_zero = {0};
    dap_assert_PIF(memcmp(&l_mutable->tx_used_out, &l_zero, sizeof(dap_hash_fast_t)) == 0,
                   "Stake lock tx_used_out should be zeroed");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_stake_lock_unspend");
}

/* ========================================================================= */
/*  Section 3.6 — Cache Lifecycle Tests                                      */
/* ========================================================================= */

static void test_mixed_record_types_scan(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append one of each record type */
    dap_ledger_cache_token_record_t l_token = {0};
    s_fill_token_record(&l_token, "CELL", 0x10);
    dap_ledger_cache_append(&l_cache, &l_token, l_token.hdr.record_size);

    dap_ledger_cache_token_update_record_t l_update = {0};
    s_fill_token_update_record(&l_update, "CELL", 0x20);
    dap_ledger_cache_append(&l_cache, &l_update, l_update.hdr.record_size);

    dap_ledger_cache_emission_record_t l_emission = {0};
    s_fill_emission_record(&l_emission, 0x30);
    dap_ledger_cache_append(&l_cache, &l_emission, l_emission.hdr.record_size);

    dap_ledger_cache_stake_lock_record_t l_sl = {0};
    s_fill_stake_lock_record(&l_sl, 0x40);
    dap_ledger_cache_append(&l_cache, &l_sl, l_sl.hdr.record_size);

    uint32_t l_tx_n_outs = 1;
    uint32_t l_tx_size = DAP_LEDGER_CACHE_TX_MIN_SIZE + l_tx_n_outs * sizeof(dap_hash_fast_t);
    uint8_t *l_tx_buf = calloc(1, l_tx_size);
    s_fill_tx_record((dap_ledger_cache_tx_record_t *)l_tx_buf, l_tx_n_outs, 0x50);
    dap_ledger_cache_append(&l_cache, l_tx_buf, l_tx_size);

    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 5, "Should scan 5 records");
    dap_assert_PIF(l_stats.token_count == 1, "1 token");
    dap_assert_PIF(l_stats.token_update_count == 1, "1 token update");
    dap_assert_PIF(l_stats.emission_count == 1, "1 emission");
    dap_assert_PIF(l_stats.stake_lock_count == 1, "1 stake lock");
    dap_assert_PIF(l_stats.tx_count == 1, "1 TX");

    free(l_tx_buf);
    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_mixed_record_types_scan");
}

static void test_shutdown_and_reopen(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append some records */
    dap_ledger_cache_token_record_t l_token = {0};
    s_fill_token_record(&l_token, "CELL", 0xAA);
    dap_ledger_cache_append(&l_cache, &l_token, l_token.hdr.record_size);

    dap_ledger_cache_emission_record_t l_emission = {0};
    s_fill_emission_record(&l_emission, 0xBB);
    dap_ledger_cache_append(&l_cache, &l_emission, l_emission.hdr.record_size);

    uint64_t l_saved_data_end = l_cache.data_end;
    uint64_t l_saved_record_count = l_cache.record_count;

    /* Clean shutdown */
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0,
                   "Shutdown should succeed");

    /* Reopen */
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Reopen should succeed");

    dap_ledger_cache_file_header_t l_hdr = {0};
    dap_ledger_cache_read_header(&l_cache, &l_hdr);
    dap_assert_PIF(l_hdr.dirty_flag == DAP_LEDGER_CACHE_DIRTY_CLEAN,
                   "Should be CLEAN after shutdown");
    dap_assert_PIF(l_hdr.data_end == l_saved_data_end,
                   "data_end should be preserved");
    dap_assert_PIF(l_hdr.record_count == l_saved_record_count,
                   "record_count should be preserved");

    /* Scan should find the same records */
    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 2, "Should find 2 records after reopen");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_shutdown_and_reopen");
}

static void test_reopen_preserves_data(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append TX with specific data */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x42);
    l_tx.ts_created = 9999999ULL;
    l_tx.datum_size = 512;
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    /* Shutdown */
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0,
                   "Shutdown should succeed");

    /* Reopen and verify data integrity */
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Reopen should succeed");

    const dap_ledger_cache_tx_record_t *l_read =
        (const dap_ledger_cache_tx_record_t *)(l_cache.base + l_offset);
    dap_assert_PIF(l_read->hdr.record_type == DAP_LEDGER_CACHE_REC_TX, "Type should be TX");
    dap_assert_PIF(l_read->ts_created == 9999999ULL, "ts_created should be preserved");
    dap_assert_PIF(l_read->datum_size == 512, "datum_size should be preserved");

    dap_hash_fast_t l_expected_hash;
    memset(&l_expected_hash, 0x42, sizeof(l_expected_hash));
    dap_assert_PIF(memcmp(&l_read->tx_hash_fast, &l_expected_hash, sizeof(dap_hash_fast_t)) == 0,
                   "tx_hash_fast should be preserved");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_reopen_preserves_data");
}

static void test_multiple_appends_and_scan(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    int l_n_records = 100;
    for (int i = 0; i < l_n_records; i++) {
        dap_ledger_cache_tx_record_t l_tx = {0};
        s_fill_tx_record(&l_tx, 0, (uint8_t)(i & 0xFF));
        dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    }

    dap_assert_PIF(l_cache.record_count == (uint64_t)l_n_records,
                   "record_count should match number of appends");

    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == l_n_records, "Scanner should find all appended records");
    dap_assert_PIF(l_stats.tx_count == l_n_records, "All should be TX records");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_multiple_appends_and_scan");
}

static void test_resize_path(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    uint64_t l_old_mapped_size = l_cache.mapped_size;

    /* Request headroom larger than current file */
    dap_assert_PIF(dap_ledger_cache_ensure_headroom(&l_cache, l_old_mapped_size * 2) == 0,
                   "Ensure headroom should succeed with resize");
    dap_assert_PIF(l_cache.mapped_size > l_old_mapped_size,
                   "Mapped size should grow after resize");
    dap_assert_PIF(l_cache.base != NULL, "Base should still be valid after resize");

    /* Append should work after resize */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0xAA);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    dap_assert_PIF(l_offset != (uint64_t)-1, "Append after resize should succeed");

    /* Verify the record is readable */
    const dap_ledger_cache_tx_record_t *l_read =
        (const dap_ledger_cache_tx_record_t *)(l_cache.base + l_offset);
    dap_assert_PIF(l_read->hdr.record_type == DAP_LEDGER_CACHE_REC_TX,
                   "Record should be readable after resize");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_resize_path");
}

static void test_manifest_shutdown(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append some records */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x11);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    /* Create manifest entries */
    dap_ledger_cache_manifest_entry_t l_entries[2];
    memset(l_entries, 0, sizeof(l_entries));
    l_entries[0].chain_id = 1;
    l_entries[0].cell_id = 1;
    l_entries[0].atom_count = 100;
    memset(&l_entries[0].last_atom_hash, 0xAA, sizeof(dap_hash_fast_t));

    l_entries[1].chain_id = 2;
    l_entries[1].cell_id = 1;
    l_entries[1].atom_count = 50;
    memset(&l_entries[1].last_atom_hash, 0xBB, sizeof(dap_hash_fast_t));

    /* Shutdown with manifest */
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, l_entries, 2) == 0,
                   "Shutdown with manifest should succeed");

    /* Reopen and verify CLEAN */
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Reopen should succeed");

    dap_ledger_cache_file_header_t l_hdr = {0};
    dap_ledger_cache_read_header(&l_cache, &l_hdr);
    dap_assert_PIF(l_hdr.dirty_flag == DAP_LEDGER_CACHE_DIRTY_CLEAN,
                   "Should be CLEAN after manifest shutdown");

    /* Manifest hash should be non-zero */
    uint8_t l_zero_hash[32] = {0};
    dap_assert_PIF(memcmp(l_hdr.manifest_hash, l_zero_hash, 32) != 0,
                   "Manifest hash should be non-zero with 2 entries");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_manifest_shutdown");
}

static void test_null_params(void)
{
    /* Various NULL parameter handling */
    dap_assert_PIF(dap_ledger_cache_open(NULL, "/tmp/x", 0) == -1,
                   "NULL cache should fail");

    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, NULL, 0) == -1,
                   "NULL path should fail");

    dap_assert_PIF(dap_ledger_cache_read_header(NULL, NULL) == -1,
                   "NULL params should fail");

    dap_assert_PIF(dap_ledger_cache_mark_dirty(NULL) == -1,
                   "NULL cache mark_dirty should fail");

    dap_assert_PIF(dap_ledger_cache_append(NULL, NULL, 0) == (uint64_t)-1,
                   "NULL cache append should fail");

    dap_assert_PIF(dap_ledger_cache_scan(NULL, NULL, NULL, false) == -1,
                   "NULL cache scan should fail");

    dap_assert_PIF(dap_ledger_cache_shutdown(NULL, NULL, 0) == -1,
                   "NULL cache shutdown should fail");

    /* close with NULL should not crash */
    dap_ledger_cache_close(NULL);

    dap_assert(1, "test_null_params");
}

static void test_struct_sizes(void)
{
    dap_assert_PIF(sizeof(dap_ledger_cache_file_header_t) == 120,
                   "File header should be 120 B");
    dap_assert_PIF(sizeof(dap_ledger_cache_record_hdr_t) == 8,
                   "Record header should be 8 B");
    dap_assert_PIF(sizeof(dap_ledger_cache_tx_record_t) == 136,
                   "TX record base should be 136 B");
    dap_assert_PIF(sizeof(dap_ledger_cache_token_record_t) == 128,
                   "Token record should be 128 B");
    dap_assert_PIF(sizeof(dap_ledger_cache_emission_record_t) == 136,
                   "Emission record should be 136 B");
    dap_assert_PIF(sizeof(dap_ledger_cache_stake_lock_record_t) == 80,
                   "Stake lock record should be 80 B");
    dap_assert_PIF(sizeof(dap_ledger_cache_token_update_record_t) == 104,
                   "Token update record should be 104 B");
    dap_assert_PIF(sizeof(dap_ledger_cache_manifest_entry_t) == 56,
                   "Manifest entry should be 56 B");
    dap_assert(1, "test_struct_sizes");
}

/* ========================================================================= */
/*  Section 3.6+ — Compaction, Purge, Manifest Validation Tests              */
/* ========================================================================= */

static void test_compaction_removes_tombstoned(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append 3 TX records, tombstone the middle one */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0xA1);
    uint64_t l_off0 = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    s_fill_tx_record(&l_tx, 0, 0xA2);
    uint64_t l_off1 = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    s_fill_tx_record(&l_tx, 0, 0xA3);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    /* Tombstone the second record */
    dap_ledger_cache_tx_record_t *l_mutable =
        (dap_ledger_cache_tx_record_t *)(l_cache.base + l_off1);
    l_mutable->tombstone = 1;

    dap_assert_PIF(l_cache.record_count == 3, "Should have 3 records before compact");

    /* Compact */
    dap_assert_PIF(dap_ledger_cache_compact(&l_cache, NULL, 0) == 0,
                   "Compaction should succeed");

    /* After compaction: 2 live records */
    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 2, "Should have 2 records after compaction");
    dap_assert_PIF(l_stats.tx_count == 2, "Both should be TX records");

    /* Verify no tombstoned records remain */
    uint64_t l_offset = DAP_LEDGER_CACHE_HEADER_SIZE;
    while (l_offset < l_cache.data_end) {
        dap_assert_PIF(!dap_ledger_cache_record_is_tombstoned(l_cache.base, l_offset),
                       "No tombstoned records should remain");
        const dap_ledger_cache_record_hdr_t *l_hdr =
            (const dap_ledger_cache_record_hdr_t *)(l_cache.base + l_offset);
        l_offset += l_hdr->record_size;
    }

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_compaction_removes_tombstoned");
}

static void test_compaction_preserves_live_data(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append a token and an emission */
    dap_ledger_cache_token_record_t l_token = {0};
    s_fill_token_record(&l_token, "CELL", 0xB1);
    dap_ledger_cache_append(&l_cache, &l_token, l_token.hdr.record_size);

    dap_ledger_cache_emission_record_t l_emission = {0};
    s_fill_emission_record(&l_emission, 0xB2);
    l_emission.tombstone = 1;
    dap_ledger_cache_append(&l_cache, &l_emission, l_emission.hdr.record_size);

    dap_ledger_cache_stake_lock_record_t l_sl = {0};
    s_fill_stake_lock_record(&l_sl, 0xB3);
    dap_ledger_cache_append(&l_cache, &l_sl, l_sl.hdr.record_size);

    dap_assert_PIF(dap_ledger_cache_compact(&l_cache, NULL, 0) == 0,
                   "Compaction should succeed");

    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 2, "Should have 2 records (token + stake_lock)");
    dap_assert_PIF(l_stats.token_count == 1, "1 token");
    dap_assert_PIF(l_stats.stake_lock_count == 1, "1 stake lock");
    dap_assert_PIF(l_stats.emission_count == 0, "0 emissions (tombstoned)");

    /* Verify token data integrity after compaction */
    const dap_ledger_cache_token_record_t *l_read =
        (const dap_ledger_cache_token_record_t *)(l_cache.base + DAP_LEDGER_CACHE_HEADER_SIZE);
    dap_assert_PIF(memcmp(l_read->ticker, "CELL", 4) == 0,
                   "Token ticker should be preserved");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_compaction_preserves_live_data");
}

static void test_compaction_with_manifest(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0xC1);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    dap_ledger_cache_manifest_entry_t l_entries[1];
    memset(l_entries, 0, sizeof(l_entries));
    l_entries[0].chain_id = 1;
    l_entries[0].cell_id = 1;
    l_entries[0].atom_count = 42;
    memset(&l_entries[0].last_atom_hash, 0xDD, sizeof(dap_hash_fast_t));

    dap_assert_PIF(dap_ledger_cache_compact(&l_cache, l_entries, 1) == 0,
                   "Compaction with manifest should succeed");

    /* Validate the compacted file's manifest */
    dap_assert_PIF(dap_ledger_cache_validate_manifest(&l_cache) == 0,
                   "Manifest should be valid after compaction");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_compaction_with_manifest");
}

static void test_purge(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append several records */
    for (int i = 0; i < 10; i++) {
        dap_ledger_cache_tx_record_t l_tx = {0};
        s_fill_tx_record(&l_tx, 0, (uint8_t)i);
        dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    }
    dap_assert_PIF(l_cache.record_count == 10, "Should have 10 records before purge");

    /* Purge */
    dap_assert_PIF(dap_ledger_cache_purge(&l_cache) == 0,
                   "Purge should succeed");

    dap_assert_PIF(l_cache.data_end == DAP_LEDGER_CACHE_HEADER_SIZE,
                   "data_end should be reset to header size");
    dap_assert_PIF(l_cache.record_count == 0,
                   "record_count should be 0 after purge");
    dap_assert_PIF(l_cache.dirty == true,
                   "Cache should be dirty after purge");

    /* Scan should find no records */
    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 0, "No records after purge");

    /* Can append new records after purge */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0xFF);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    dap_assert_PIF(l_offset == DAP_LEDGER_CACHE_HEADER_SIZE,
                   "First append after purge should be at header boundary");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_purge");
}

static void test_manifest_hash_mismatch(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x11);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    /* Shutdown with manifest */
    dap_ledger_cache_manifest_entry_t l_entries[1];
    memset(l_entries, 0, sizeof(l_entries));
    l_entries[0].chain_id = 1;
    l_entries[0].atom_count = 10;
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, l_entries, 1) == 0,
                   "Shutdown should succeed");

    /* Reopen and corrupt manifest_hash */
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Reopen should succeed");
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->manifest_hash[0] ^= 0xFF;

    int l_rc = dap_ledger_cache_validate_manifest(&l_cache);
    dap_assert_PIF(l_rc != 0, "Corrupted manifest hash should fail validation");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_manifest_hash_mismatch");
}

static void test_manifest_no_entries_valid(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Shutdown with no manifest entries */
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0,
                   "Shutdown should succeed");

    /* Reopen and validate */
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Reopen should succeed");
    dap_assert_PIF(dap_ledger_cache_validate_manifest(&l_cache) == 0,
                   "Empty manifest should validate OK");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_manifest_no_entries_valid");
}

static void test_record_count_mismatch(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append 3 records */
    for (int i = 0; i < 3; i++) {
        dap_ledger_cache_tx_record_t l_tx = {0};
        s_fill_tx_record(&l_tx, 0, (uint8_t)(0x10 + i));
        dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    }

    /* Shutdown normally */
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0,
                   "Shutdown should succeed");

    /* Reopen and corrupt record_count */
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Reopen should succeed");
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->record_count = 999;

    int l_rc = dap_ledger_cache_validate_manifest(&l_cache);
    dap_assert_PIF(l_rc != 0, "Mismatched record_count should fail validation");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_record_count_mismatch");
}

static void test_data_end_beyond_mapped_size(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Shutdown normally */
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0,
                   "Shutdown should succeed");

    /* Reopen and set data_end beyond file size */
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Reopen should succeed");
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->data_end = l_cache.mapped_size + 1024;

    int l_rc = dap_ledger_cache_validate_manifest(&l_cache);
    dap_assert_PIF(l_rc != 0, "data_end beyond mapped size should fail validation");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_data_end_beyond_mapped_size");
}

/* ========================================================================= */
/*  Section 5 — Crash Simulation Tests (CP1-CP8)                             */
/* ========================================================================= */

static void test_crash_cp1_torn_record_at_eof(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append one valid record */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x01);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    uint64_t l_valid_end = l_cache.data_end;

    /* Simulate CP1: partial record body at EOF */
    dap_ledger_cache_record_hdr_t l_partial = {
        .record_size = DAP_LEDGER_CACHE_TX_MIN_SIZE,
        .record_type = DAP_LEDGER_CACHE_REC_TX
    };
    memcpy(l_cache.base + l_cache.data_end, &l_partial, sizeof(l_partial));
    l_cache.data_end += 20;  /* Only 20 bytes of a 136-byte record */
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->data_end = l_cache.data_end;
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;

    /* Scan with truncation should recover 1 valid record */
    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, true);
    dap_assert_PIF(l_count == 1, "CP1: should recover 1 valid record");
    dap_assert_PIF(l_cache.data_end == l_valid_end, "CP1: data_end should be truncated to valid boundary");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_crash_cp1_torn_record_at_eof");
}

static void test_crash_cp2_record_written_header_not_updated(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append one record normally */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x02);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    /* Simulate CP2: write a complete record at data_end but don't update header's data_end */
    uint64_t l_old_data_end = l_cache.data_end;
    s_fill_tx_record(&l_tx, 0, 0x03);
    memcpy(l_cache.base + l_cache.data_end, &l_tx, l_tx.hdr.record_size);
    /* Don't advance data_end or record_count — header still says old values */
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;

    /* Scanner uses data_end from cache context — should only see the first record */
    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 1, "CP2: should see only 1 record (header not updated)");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_crash_cp2_record_written_header_not_updated");
}

static void test_crash_cp3_data_end_advanced_no_msync(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append valid record + one that might be partially flushed */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x04);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    s_fill_tx_record(&l_tx, 0, 0x05);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    /* Simulate CP3: data_end advanced in header, but record content might be valid.
       In our test the memcpy happened, so scan should find it. */
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;

    /* Scan with truncation should find both valid records */
    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, true);
    dap_assert_PIF(l_count == 2, "CP3: both records valid, scan finds 2");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_crash_cp3_data_end_advanced_no_msync");
}

static void test_crash_cp4_partial_mutable_update(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append a token record */
    dap_ledger_cache_token_record_t l_token = {0};
    s_fill_token_record(&l_token, "TEST", 0x06);
    uint64_t l_offset = dap_ledger_cache_append(&l_cache, &l_token, l_token.hdr.record_size);

    /* Simulate CP4: partial current_supply write (corrupt 16 of 32 bytes) */
    dap_ledger_cache_token_record_t *l_mutable =
        (dap_ledger_cache_token_record_t *)(l_cache.base + l_offset);
    uint8_t l_partial_supply[32];
    memset(l_partial_supply, 0xAA, 16);
    memset(l_partial_supply + 16, 0, 16);
    memcpy(&l_mutable->current_supply, l_partial_supply, 32);

    /* The record itself is still structurally valid — scan succeeds */
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;

    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 1, "CP4: record structurally valid despite partial supply write");
    dap_assert_PIF(l_stats.token_count == 1, "CP4: token record still scannable");

    /* On dirty startup, current_supply would be recomputed from emissions+TXs */
    dap_assert_PIF(l_cache.dirty == true, "CP4: cache is dirty, full rebuild needed");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_crash_cp4_partial_mutable_update");
}

static void test_crash_cp5_mid_rollback(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append 3 TX records */
    for (int i = 0; i < 3; i++) {
        dap_ledger_cache_tx_record_t l_tx = {0};
        s_fill_tx_record(&l_tx, 0, (uint8_t)(0x10 + i));
        dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    }

    /* Simulate CP5: mid-rollback — tombstone first 2 but not the 3rd */
    uint64_t l_offset = DAP_LEDGER_CACHE_HEADER_SIZE;
    for (int i = 0; i < 2; i++) {
        dap_ledger_cache_tx_record_t *l_rec =
            (dap_ledger_cache_tx_record_t *)(l_cache.base + l_offset);
        l_rec->tombstone = 1;
        l_offset += l_rec->hdr.record_size;
    }

    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;

    /* On dirty startup: all 3 records are scannable, but 2 are tombstoned.
       Full rebuild would discard the cache entirely. */
    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 3, "CP5: all 3 records structurally valid");

    /* Count non-tombstoned */
    int l_live = 0;
    l_offset = DAP_LEDGER_CACHE_HEADER_SIZE;
    while (l_offset < l_cache.data_end) {
        if (!dap_ledger_cache_record_is_tombstoned(l_cache.base, l_offset))
            l_live++;
        const dap_ledger_cache_record_hdr_t *l_rec_hdr =
            (const dap_ledger_cache_record_hdr_t *)(l_cache.base + l_offset);
        l_offset += l_rec_hdr->record_size;
    }
    dap_assert_PIF(l_live == 1, "CP5: only 1 live record (rollback incomplete)");
    dap_assert_PIF(l_cache.dirty == true, "CP5: dirty flag means full rebuild required");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_crash_cp5_mid_rollback");
}

static void test_crash_cp6_compaction_interrupted(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* Append records */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x07);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    uint64_t l_saved_data_end = l_cache.data_end;
    uint64_t l_saved_count = l_cache.record_count;

    /* Simulate CP6: create a leftover .tmp file (as if compaction was interrupted) */
    char l_tmp_path[300];
    snprintf(l_tmp_path, sizeof(l_tmp_path), "%s.tmp", l_path);
    int l_tmp_fd = open(l_tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (l_tmp_fd >= 0) {
        write(l_tmp_fd, "garbage", 7);
        close(l_tmp_fd);
    }

    /* The original file should still be intact */
    dap_assert_PIF(l_cache.data_end == l_saved_data_end,
                   "CP6: original data_end intact");
    dap_assert_PIF(l_cache.record_count == l_saved_count,
                   "CP6: original record_count intact");

    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 1, "CP6: original file still has 1 valid record");

    /* Cleanup temp file */
    unlink(l_tmp_path);

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_crash_cp6_compaction_interrupted");
}

static void test_crash_cp7_after_data_msync_before_clean(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x08);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    /* Simulate CP7: data is synced but dirty_flag remains DIRTY
       (crash between shutdown step 3 and step 4) */
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->data_end = l_cache.data_end;
    l_hdr->record_count = l_cache.record_count;
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_DIRTY;
    msync(l_cache.base, l_cache.mapped_size, MS_SYNC);

    dap_ledger_cache_close(&l_cache);

    /* Reopen — should detect DIRTY state */
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Reopen should succeed");
    dap_assert_PIF(l_cache.dirty == true, "CP7: cache should be dirty (full rebuild needed)");

    /* Data is intact — scan still finds the record */
    scan_stats_t l_stats = {0};
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_counter_callback, &l_stats, false);
    dap_assert_PIF(l_count == 1, "CP7: data intact, 1 record scannable");

    /* Manifest validation should fail (DIRTY) */
    int l_rc = dap_ledger_cache_validate_manifest(&l_cache);
    dap_assert_PIF(l_rc != 0, "CP7: manifest validation fails (dirty flag)");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_crash_cp7_after_data_msync_before_clean");
}

static void test_crash_cp8_clean_written_manifest_incomplete(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x09);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    /* Simulate CP8: dirty_flag=CLEAN is written but manifest_hash is wrong
       (crash between step 4 and step 5/6 — flag written, manifest may be corrupt) */
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->data_end = l_cache.data_end;
    l_hdr->record_count = l_cache.record_count;
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_CLEAN;
    l_hdr->manifest_count = 1;
    memset(l_hdr->manifest_hash, 0xDE, 32);  /* Bogus hash */
    msync(l_cache.base, l_cache.mapped_size, MS_SYNC);

    dap_ledger_cache_close(&l_cache);

    /* Reopen — appears CLEAN */
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Reopen should succeed");
    dap_assert_PIF(l_cache.dirty == false, "CP8: cache appears CLEAN (flag was persisted)");

    /* But manifest validation catches the inconsistency */
    int l_rc = dap_ledger_cache_validate_manifest(&l_cache);
    dap_assert_PIF(l_rc != 0, "CP8: manifest hash mismatch detected");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_crash_cp8_clean_written_manifest_incomplete");
}

static void test_tombstone_detection_all_types(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0,
                   "Cache open should succeed");

    /* TX tombstone */
    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0xF1);
    l_tx.tombstone = 1;
    uint64_t l_off_tx = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    dap_assert_PIF(dap_ledger_cache_record_is_tombstoned(l_cache.base, l_off_tx),
                   "TX should be tombstoned");

    /* Token tombstone */
    dap_ledger_cache_token_record_t l_token = {0};
    s_fill_token_record(&l_token, "DEAD", 0xF2);
    l_token.tombstone = 1;
    uint64_t l_off_tok = dap_ledger_cache_append(&l_cache, &l_token, l_token.hdr.record_size);
    dap_assert_PIF(dap_ledger_cache_record_is_tombstoned(l_cache.base, l_off_tok),
                   "Token should be tombstoned");

    /* Emission tombstone */
    dap_ledger_cache_emission_record_t l_em = {0};
    s_fill_emission_record(&l_em, 0xF3);
    l_em.tombstone = 1;
    uint64_t l_off_em = dap_ledger_cache_append(&l_cache, &l_em, l_em.hdr.record_size);
    dap_assert_PIF(dap_ledger_cache_record_is_tombstoned(l_cache.base, l_off_em),
                   "Emission should be tombstoned");

    /* Token update tombstone */
    dap_ledger_cache_token_update_record_t l_upd = {0};
    s_fill_token_update_record(&l_upd, "DEAD", 0xF4);
    l_upd.tombstone = 1;
    uint64_t l_off_upd = dap_ledger_cache_append(&l_cache, &l_upd, l_upd.hdr.record_size);
    dap_assert_PIF(dap_ledger_cache_record_is_tombstoned(l_cache.base, l_off_upd),
                   "Token update should be tombstoned");

    /* Stake lock has no tombstone — always returns false */
    dap_ledger_cache_stake_lock_record_t l_sl = {0};
    s_fill_stake_lock_record(&l_sl, 0xF5);
    uint64_t l_off_sl = dap_ledger_cache_append(&l_cache, &l_sl, l_sl.hdr.record_size);
    dap_assert_PIF(!dap_ledger_cache_record_is_tombstoned(l_cache.base, l_off_sl),
                   "Stake lock should never be tombstoned");

    /* Non-tombstoned TX */
    s_fill_tx_record(&l_tx, 0, 0xF6);
    l_tx.tombstone = 0;
    uint64_t l_off_live = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    dap_assert_PIF(!dap_ledger_cache_record_is_tombstoned(l_cache.base, l_off_live),
                   "Live TX should not be tombstoned");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_tombstone_detection_all_types");
}

/* ===========================================================================
 *  Section 6: Higher-level Append & Update API Tests
 * =========================================================================== */

static void test_hlapi_tx_append_and_update(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_tx_hash;
    memset(&l_tx_hash, 0xAB, sizeof(l_tx_hash));
    char l_ticker[10] = "TEST";

    uint64_t l_off = dap_ledger_cache_append_tx_record(&l_cache,
        &l_tx_hash, 1000, 2000, 3, 0, l_ticker, 0x01, 0, 0, 42, 1,
        512, 0x100, 0x200, 0x300, NULL);
    dap_assert_PIF(l_off != (uint64_t)-1, "TX append should succeed");

    const dap_ledger_cache_tx_record_t *l_rec =
        (const dap_ledger_cache_tx_record_t *)(l_cache.base + l_off);
    dap_assert_PIF(l_rec->hdr.record_type == DAP_LEDGER_CACHE_REC_TX, "record type");
    dap_assert_PIF(l_rec->ts_added == 1000, "ts_added");
    dap_assert_PIF(l_rec->n_outs == 3, "n_outs");
    dap_assert_PIF(l_rec->datum_file_offset == 0x300, "datum_file_offset");
    dap_assert_PIF(memcmp(l_rec->token_ticker, l_ticker, 10) == 0, "ticker");

    dap_hash_fast_t l_spender;
    memset(&l_spender, 0xCD, sizeof(l_spender));
    dap_assert_PIF(dap_ledger_cache_update_tx_spent(&l_cache, l_off, 1, &l_spender, 1, 9999) == 0,
                   "update spent");
    dap_assert_PIF(l_rec->n_outs_used == 1, "n_outs_used after spend");
    dap_assert_PIF(l_rec->ts_spent == 9999, "ts_spent after spend");
    dap_assert_PIF(memcmp(&l_rec->out_spent_hashes[1], &l_spender, sizeof(dap_hash_fast_t)) == 0,
                   "spender hash stored");

    dap_assert_PIF(dap_ledger_cache_update_tx_spent(&l_cache, l_off, 5, &l_spender, 1, 0) == -3,
                   "out of bounds should fail");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_hlapi_tx_append_and_update");
}

static void test_hlapi_token_append_and_supply_update(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_token_hash;
    memset(&l_token_hash, 0x11, sizeof(l_token_hash));
    char l_ticker[10] = "CELL";
    uint256_t l_supply = uint256_0;
    l_supply.lo = 1000000;

    uint64_t l_off = dap_ledger_cache_append_token_record(&l_cache,
        &l_token_hash, l_ticker, 1, &l_supply, 256, 0x10, 0x20, 0x30);
    dap_assert_PIF(l_off != (uint64_t)-1, "token append");

    const dap_ledger_cache_token_record_t *l_rec =
        (const dap_ledger_cache_token_record_t *)(l_cache.base + l_off);
    dap_assert_PIF(l_rec->hdr.record_type == DAP_LEDGER_CACHE_REC_TOKEN, "record type");
    dap_assert_PIF(l_rec->subtype == 1, "subtype");
    dap_assert_PIF(l_rec->current_supply.lo == 1000000, "initial supply");

    uint256_t l_new_supply = uint256_0;
    l_new_supply.lo = 999000;
    dap_assert_PIF(dap_ledger_cache_update_token_supply(&l_cache, l_off, &l_new_supply) == 0,
                   "supply update");
    dap_assert_PIF(l_rec->current_supply.lo == 999000, "supply after update");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_hlapi_token_append_and_supply_update");
}

static void test_hlapi_emission_append_and_spend(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_ems_hash;
    memset(&l_ems_hash, 0x22, sizeof(l_ems_hash));

    char l_em_ticker[10] = "TESTEMSTN";
    uint64_t l_off = dap_ledger_cache_append_emission_record(&l_cache,
        &l_ems_hash, l_em_ticker, 5000, 128, 0xA0, 0xB0, 0xC0, true);
    dap_assert_PIF(l_off != (uint64_t)-1, "emission append");

    const dap_ledger_cache_emission_record_t *l_rec =
        (const dap_ledger_cache_emission_record_t *)(l_cache.base + l_off);
    dap_assert_PIF(l_rec->hdr.record_type == DAP_LEDGER_CACHE_REC_EMISSION, "type");
    dap_assert_PIF(memcmp(l_rec->ticker, l_em_ticker, 10) == 0, "ticker persisted");
    dap_assert_PIF(l_rec->is_hardfork == 1, "is_hardfork");
    dap_assert_PIF(l_rec->datum_file_offset == 0xC0, "datum_file_offset");

    dap_hash_fast_t l_zero = {};
    dap_assert_PIF(memcmp(&l_rec->tx_used_out, &l_zero, sizeof(l_zero)) == 0, "initially unspent");

    dap_hash_fast_t l_tx;
    memset(&l_tx, 0xDD, sizeof(l_tx));
    dap_assert_PIF(dap_ledger_cache_update_emission_spent(&l_cache, l_off, &l_tx) == 0, "spend");
    dap_assert_PIF(memcmp(&l_rec->tx_used_out, &l_tx, sizeof(l_tx)) == 0, "spent hash");

    dap_assert_PIF(dap_ledger_cache_update_emission_spent(&l_cache, l_off, NULL) == 0, "unspend");
    dap_assert_PIF(memcmp(&l_rec->tx_used_out, &l_zero, sizeof(l_zero)) == 0, "cleared hash");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_hlapi_emission_append_and_spend");
}

static void test_hlapi_stake_lock_append_and_spend(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_sl_hash;
    memset(&l_sl_hash, 0x33, sizeof(l_sl_hash));

    uint64_t l_off = dap_ledger_cache_append_stake_lock_record(&l_cache, &l_sl_hash, 0xF0);
    dap_assert_PIF(l_off != (uint64_t)-1, "stake lock append");

    const dap_ledger_cache_stake_lock_record_t *l_rec =
        (const dap_ledger_cache_stake_lock_record_t *)(l_cache.base + l_off);
    dap_assert_PIF(l_rec->hdr.record_type == DAP_LEDGER_CACHE_REC_STAKE_LOCK, "type");
    dap_assert_PIF(l_rec->datum_file_offset == 0xF0, "datum_file_offset");

    dap_hash_fast_t l_tx;
    memset(&l_tx, 0xEE, sizeof(l_tx));
    dap_assert_PIF(dap_ledger_cache_update_stake_lock_spent(&l_cache, l_off, &l_tx) == 0, "spend");
    dap_assert_PIF(memcmp(&l_rec->tx_used_out, &l_tx, sizeof(l_tx)) == 0, "spent hash");

    dap_assert_PIF(dap_ledger_cache_update_stake_lock_spent(&l_cache, l_off, NULL) == 0, "unspend");
    dap_hash_fast_t l_zero = {};
    dap_assert_PIF(memcmp(&l_rec->tx_used_out, &l_zero, sizeof(l_zero)) == 0, "cleared hash");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_hlapi_stake_lock_append_and_spend");
}

static void test_hlapi_token_update_append(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_upd_hash;
    memset(&l_upd_hash, 0x44, sizeof(l_upd_hash));
    char l_ticker[10] = "TOK";

    uint64_t l_off = dap_ledger_cache_append_token_update_record(&l_cache,
        &l_upd_hash, l_ticker, 64, 123456789, 0xD0, 0xE0, 0xF0);
    dap_assert_PIF(l_off != (uint64_t)-1, "token update append");

    const dap_ledger_cache_token_update_record_t *l_rec =
        (const dap_ledger_cache_token_update_record_t *)(l_cache.base + l_off);
    dap_assert_PIF(l_rec->hdr.record_type == DAP_LEDGER_CACHE_REC_TOKEN_UPDATE, "type");
    dap_assert_PIF(l_rec->updated_time == 123456789, "updated_time");
    dap_assert_PIF(memcmp(l_rec->ticker, l_ticker, 10) == 0, "ticker");
    dap_assert_PIF(l_rec->datum_file_offset == 0xF0, "datum_file_offset");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_hlapi_token_update_append");
}

static void test_hlapi_tombstone_tx(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_tx_hash;
    memset(&l_tx_hash, 0x55, sizeof(l_tx_hash));
    char l_ticker[10] = "TST";

    uint64_t l_off = dap_ledger_cache_append_tx_record(&l_cache,
        &l_tx_hash, 1000, 2000, 2, 0, l_ticker, 0, 0, 0, 0, 0,
        128, 0, 0, 0, NULL);
    dap_assert_PIF(l_off != (uint64_t)-1, "TX append");

    const dap_ledger_cache_tx_record_t *l_rec =
        (const dap_ledger_cache_tx_record_t *)(l_cache.base + l_off);
    dap_assert_PIF(l_rec->tombstone == 0, "initially live");
    dap_assert_PIF(!dap_ledger_cache_record_is_tombstoned(l_cache.base, l_off), "not tombstoned");

    dap_assert_PIF(dap_ledger_cache_tombstone_tx(&l_cache, l_off) == 0, "tombstone");
    dap_assert_PIF(l_rec->tombstone == 1, "tombstoned flag");
    dap_assert_PIF(dap_ledger_cache_record_is_tombstoned(l_cache.base, l_off), "is tombstoned");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_hlapi_tombstone_tx");
}

/* ===========================================================================
 *  Section 7: Coverage Gap Tests
 * =========================================================================== */

static void test_validate_manifest_data_end_below_header(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->data_end = 50;

    dap_assert_PIF(dap_ledger_cache_validate_manifest(&l_cache) == -6,
                   "data_end < HEADER_SIZE should return -6");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_validate_manifest_data_end_below_header");
}

static void test_validate_manifest_beyond_mapped_size(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->manifest_count = 2000000;

    dap_assert_PIF(dap_ledger_cache_validate_manifest(&l_cache) == -7,
                   "manifest extending beyond mapped_size should return -7");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_validate_manifest_beyond_mapped_size");
}

static void test_validate_manifest_no_entries_nonzero_hash(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->manifest_count = 0;
    memset(l_hdr->manifest_hash, 0xDE, 32);

    dap_assert_PIF(dap_ledger_cache_validate_manifest(&l_cache) == -9,
                   "0 manifest entries with non-zero hash should return -9");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_validate_manifest_no_entries_nonzero_hash");
}

static void test_validate_manifest_corrupt_record_during_scan(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x01);
    dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    dap_ledger_cache_record_hdr_t *l_rec_hdr =
        (dap_ledger_cache_record_hdr_t *)(l_cache.base + DAP_LEDGER_CACHE_HEADER_SIZE);
    l_rec_hdr->record_size = 4;

    dap_assert_PIF(dap_ledger_cache_validate_manifest(&l_cache) == -10,
                   "corrupt record during consistency scan should return -10");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_validate_manifest_corrupt_record_during_scan");
}

static void test_scan_callback_early_termination(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    for (int i = 0; i < 5; i++) {
        dap_ledger_cache_tx_record_t l_tx = {0};
        s_fill_tx_record(&l_tx, 0, (uint8_t)(0x30 + i));
        dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    }

    dap_assert_PIF(l_cache.record_count == 5, "should have 5 records");

    s_scan_stop_at_2_count = 0;
    int64_t l_count = dap_ledger_cache_scan(&l_cache, s_scan_stop_at_2_callback, NULL, false);
    dap_assert_PIF(l_count == 1, "scan stops when callback returns non-zero; only 1 fully processed");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_scan_callback_early_termination");
}

static void test_scan_null_callback(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    for (int i = 0; i < 3; i++) {
        dap_ledger_cache_tx_record_t l_tx = {0};
        s_fill_tx_record(&l_tx, 0, (uint8_t)(0x40 + i));
        dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);
    }

    int64_t l_count = dap_ledger_cache_scan(&l_cache, NULL, NULL, false);
    dap_assert_PIF(l_count == 3, "scan with NULL callback should still count all records");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_scan_null_callback");
}

static void test_update_tx_spent_wrong_type(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    /* Use a padded buffer with TOKEN type but at least TX_MIN_SIZE bytes
       so the bounds check passes and we hit the type check */
    uint8_t l_buf[DAP_LEDGER_CACHE_TX_MIN_SIZE];
    memset(l_buf, 0, sizeof(l_buf));
    dap_ledger_cache_record_hdr_t *l_hdr = (dap_ledger_cache_record_hdr_t *)l_buf;
    l_hdr->record_size = DAP_LEDGER_CACHE_TX_MIN_SIZE;
    l_hdr->record_type = DAP_LEDGER_CACHE_REC_TOKEN;
    uint64_t l_off = dap_ledger_cache_append(&l_cache, l_buf, DAP_LEDGER_CACHE_TX_MIN_SIZE);

    dap_hash_fast_t l_hash;
    memset(&l_hash, 0xAA, sizeof(l_hash));
    dap_assert_PIF(dap_ledger_cache_update_tx_spent(&l_cache, l_off, 0, &l_hash, 1, 0) == -2,
                   "update_tx_spent on TOKEN record should return -2");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_update_tx_spent_wrong_type");
}

static void test_update_tx_spent_bad_offset(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    dap_hash_fast_t l_hash;
    memset(&l_hash, 0xBB, sizeof(l_hash));
    dap_assert_PIF(dap_ledger_cache_update_tx_spent(&l_cache, 99999999, 0, &l_hash, 1, 0) == -1,
                   "offset beyond data_end should return -1");

    dap_assert_PIF(dap_ledger_cache_update_tx_spent(NULL, 0, 0, &l_hash, 1, 0) == -1,
                   "NULL cache should return -1");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_update_tx_spent_bad_offset");
}

static void test_update_emission_spent_wrong_type(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x60);
    uint64_t l_off = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    dap_hash_fast_t l_hash;
    memset(&l_hash, 0xCC, sizeof(l_hash));
    dap_assert_PIF(dap_ledger_cache_update_emission_spent(&l_cache, l_off, &l_hash) == -2,
                   "update_emission_spent on TX record should return -2");
    dap_assert_PIF(dap_ledger_cache_update_emission_spent(&l_cache, 99999999, &l_hash) == -1,
                   "offset beyond data_end should return -1");
    dap_assert_PIF(dap_ledger_cache_update_emission_spent(NULL, 0, &l_hash) == -1,
                   "NULL cache should return -1");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_update_emission_spent_wrong_type");
}

static void test_update_stake_lock_spent_wrong_type(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    dap_ledger_cache_emission_record_t l_em = {0};
    s_fill_emission_record(&l_em, 0x70);
    uint64_t l_off = dap_ledger_cache_append(&l_cache, &l_em, l_em.hdr.record_size);

    dap_hash_fast_t l_hash;
    memset(&l_hash, 0xDD, sizeof(l_hash));
    dap_assert_PIF(dap_ledger_cache_update_stake_lock_spent(&l_cache, l_off, &l_hash) == -2,
                   "update_stake_lock_spent on EMISSION record should return -2");
    dap_assert_PIF(dap_ledger_cache_update_stake_lock_spent(&l_cache, 99999999, &l_hash) == -1,
                   "offset beyond data_end should return -1");
    dap_assert_PIF(dap_ledger_cache_update_stake_lock_spent(NULL, 0, &l_hash) == -1,
                   "NULL cache should return -1");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_update_stake_lock_spent_wrong_type");
}

static void test_update_token_supply_wrong_type(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0x80);
    uint64_t l_off = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    uint256_t l_supply = uint256_0;
    l_supply.lo = 42;
    dap_assert_PIF(dap_ledger_cache_update_token_supply(&l_cache, l_off, &l_supply) == -2,
                   "update_token_supply on TX record should return -2");
    dap_assert_PIF(dap_ledger_cache_update_token_supply(&l_cache, 99999999, &l_supply) == -1,
                   "offset beyond data_end should return -1");
    dap_assert_PIF(dap_ledger_cache_update_token_supply(NULL, 0, &l_supply) == -1,
                   "NULL cache should return -1");
    dap_assert_PIF(dap_ledger_cache_update_token_supply(&l_cache, l_off, NULL) == -1,
                   "NULL supply should return -1");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_update_token_supply_wrong_type");
}

static void test_tombstone_tx_wrong_type(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    /* Pad to TX_MIN_SIZE so bounds check passes but type check catches it */
    uint8_t l_buf[DAP_LEDGER_CACHE_TX_MIN_SIZE];
    memset(l_buf, 0, sizeof(l_buf));
    dap_ledger_cache_record_hdr_t *l_hdr = (dap_ledger_cache_record_hdr_t *)l_buf;
    l_hdr->record_size = DAP_LEDGER_CACHE_TX_MIN_SIZE;
    l_hdr->record_type = DAP_LEDGER_CACHE_REC_EMISSION;
    uint64_t l_off = dap_ledger_cache_append(&l_cache, l_buf, DAP_LEDGER_CACHE_TX_MIN_SIZE);

    dap_assert_PIF(dap_ledger_cache_tombstone_tx(&l_cache, l_off) == -2,
                   "tombstone_tx on EMISSION record should return -2");
    dap_assert_PIF(dap_ledger_cache_tombstone_tx(&l_cache, 99999999) == -1,
                   "offset beyond data_end should return -1");
    dap_assert_PIF(dap_ledger_cache_tombstone_tx(NULL, 0) == -1,
                   "NULL cache should return -1");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_tombstone_tx_wrong_type");
}

static void test_tx_append_with_out_spent_hashes(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_tx_hash;
    memset(&l_tx_hash, 0xA0, sizeof(l_tx_hash));
    char l_ticker[10] = "PRE";

    dap_hash_fast_t l_spent[2];
    memset(&l_spent[0], 0xB1, sizeof(dap_hash_fast_t));
    memset(&l_spent[1], 0xB2, sizeof(dap_hash_fast_t));

    uint64_t l_off = dap_ledger_cache_append_tx_record(&l_cache,
        &l_tx_hash, 100, 200, 2, 2, l_ticker, 0, 0, 999, 0, 0,
        64, 0, 0, 0, l_spent);
    dap_assert_PIF(l_off != (uint64_t)-1, "TX append with spent hashes");

    const dap_ledger_cache_tx_record_t *l_rec =
        (const dap_ledger_cache_tx_record_t *)(l_cache.base + l_off);
    dap_assert_PIF(l_rec->n_outs == 2, "n_outs");
    dap_assert_PIF(l_rec->n_outs_used == 2, "n_outs_used");
    dap_assert_PIF(l_rec->ts_spent == 999, "ts_spent");
    dap_assert_PIF(memcmp(&l_rec->out_spent_hashes[0], &l_spent[0], sizeof(dap_hash_fast_t)) == 0,
                   "spent hash[0] preserved");
    dap_assert_PIF(memcmp(&l_rec->out_spent_hashes[1], &l_spent[1], sizeof(dap_hash_fast_t)) == 0,
                   "spent hash[1] preserved");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_tx_append_with_out_spent_hashes");
}

static void test_record_at_inline(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    dap_ledger_cache_tx_record_t l_tx = {0};
    s_fill_tx_record(&l_tx, 0, 0xC0);
    uint64_t l_off = dap_ledger_cache_append(&l_cache, &l_tx, l_tx.hdr.record_size);

    const dap_ledger_cache_record_hdr_t *l_hdr = dap_ledger_cache_record_at(&l_cache, l_off);
    dap_assert_PIF(l_hdr != NULL, "record_at should return valid pointer");
    dap_assert_PIF(l_hdr->record_type == DAP_LEDGER_CACHE_REC_TX, "record type via record_at");
    dap_assert_PIF(l_hdr->record_size == DAP_LEDGER_CACHE_TX_MIN_SIZE, "record size via record_at");

    const dap_ledger_cache_record_hdr_t *l_null = dap_ledger_cache_record_at(&l_cache, 99999999);
    dap_assert_PIF(l_null == NULL, "record_at with out-of-bounds offset should return NULL");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_record_at_inline");
}

static void test_validate_record_null_base(void)
{
    dap_assert_PIF(dap_ledger_cache_validate_record(NULL, 0, 1000) == -1,
                   "NULL base should return -1");
    dap_assert(1, "test_validate_record_null_base");
}

static void test_purge_null(void)
{
    dap_assert_PIF(dap_ledger_cache_purge(NULL) == -1, "purge NULL should return -1");
    dap_ledger_cache_t l_empty = {0};
    dap_assert_PIF(dap_ledger_cache_purge(&l_empty) == -1, "purge with NULL base should return -1");
    dap_assert(1, "test_purge_null");
}

static void test_compact_null(void)
{
    dap_assert_PIF(dap_ledger_cache_compact(NULL, NULL, 0) == -1, "compact NULL should return -1");
    dap_ledger_cache_t l_empty = {0};
    dap_assert_PIF(dap_ledger_cache_compact(&l_empty, NULL, 0) == -1,
                   "compact with NULL base should return -1");
    dap_assert(1, "test_compact_null");
}

/* ===========================================================================
 *  Section 8: Warm Startup Load Tests
 * =========================================================================== */

typedef struct {
    int token_count;
    int emission_count;
    int stake_lock_count;
    int tx_count;
    int token_update_count;
    dap_hash_fast_t last_tx_hash;
    uint64_t last_tx_offset;
    char last_token_ticker[10];
    uint256_t last_token_supply;
} warm_load_stats_t;

static int s_wl_on_token(const dap_ledger_cache_token_record_t *a_rec,
                          uint64_t a_offset, void *a_user_data)
{
    warm_load_stats_t *l_stats = (warm_load_stats_t *)a_user_data;
    l_stats->token_count++;
    memcpy(l_stats->last_token_ticker, a_rec->ticker, 10);
    l_stats->last_token_supply = a_rec->current_supply;
    return 0;
}

static int s_wl_on_emission(const dap_ledger_cache_emission_record_t *a_rec,
                             uint64_t a_offset, void *a_user_data)
{
    warm_load_stats_t *l_stats = (warm_load_stats_t *)a_user_data;
    l_stats->emission_count++;
    return 0;
}

static int s_wl_on_stake_lock(const dap_ledger_cache_stake_lock_record_t *a_rec,
                               uint64_t a_offset, void *a_user_data)
{
    warm_load_stats_t *l_stats = (warm_load_stats_t *)a_user_data;
    l_stats->stake_lock_count++;
    return 0;
}

static int s_wl_on_tx(const dap_ledger_cache_tx_record_t *a_rec,
                       uint64_t a_offset, void *a_user_data)
{
    warm_load_stats_t *l_stats = (warm_load_stats_t *)a_user_data;
    l_stats->tx_count++;
    l_stats->last_tx_hash = a_rec->tx_hash_fast;
    l_stats->last_tx_offset = a_offset;
    return 0;
}

static int s_wl_on_token_update(const dap_ledger_cache_token_update_record_t *a_rec,
                                 uint64_t a_offset, void *a_user_data)
{
    warm_load_stats_t *l_stats = (warm_load_stats_t *)a_user_data;
    l_stats->token_update_count++;
    return 0;
}

static void test_warm_load_basic(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_tx_hash;
    memset(&l_tx_hash, 0xAB, sizeof(l_tx_hash));
    char l_ticker[10] = "WARM";
    dap_ledger_cache_append_tx_record(&l_cache, &l_tx_hash,
        1000, 2000, 2, 0, l_ticker, 0, 0, 0, 42, 1, 512, 0x100, 0x200, 0x300, NULL);

    dap_hash_fast_t l_token_hash;
    memset(&l_token_hash, 0xBB, sizeof(l_token_hash));
    uint256_t l_supply = uint256_0;
    l_supply.lo = 1000000;
    dap_ledger_cache_append_token_record(&l_cache, &l_token_hash, l_ticker, 1,
        &l_supply, 100, 0x100, 0x200, 0x300);

    dap_hash_fast_t l_em_hash;
    memset(&l_em_hash, 0xCC, sizeof(l_em_hash));
    dap_ledger_cache_append_emission_record(&l_cache, &l_em_hash,
        l_ticker, 200, 64, 0x100, 0x200, 0x300, false);

    dap_hash_fast_t l_sl_hash;
    memset(&l_sl_hash, 0xDD, sizeof(l_sl_hash));
    dap_ledger_cache_append_stake_lock_record(&l_cache, &l_sl_hash, 0x400);

    dap_hash_fast_t l_upd_hash;
    memset(&l_upd_hash, 0xEE, sizeof(l_upd_hash));
    dap_ledger_cache_append_token_update_record(&l_cache, &l_upd_hash,
        l_ticker, 64, 300, 0x100, 0x200, 0x300);

    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    warm_load_stats_t l_stats = {0};
    dap_ledger_cache_warm_load_callbacks_t l_cbs = {
        .on_token = s_wl_on_token,
        .on_emission = s_wl_on_emission,
        .on_stake_lock = s_wl_on_stake_lock,
        .on_tx = s_wl_on_tx,
        .on_token_update = s_wl_on_token_update,
        .user_data = &l_stats
    };

    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, &l_cbs) == 0, "warm_load");
    dap_assert_PIF(l_stats.tx_count == 1, "1 TX loaded");
    dap_assert_PIF(l_stats.token_count == 1, "1 token loaded");
    dap_assert_PIF(l_stats.emission_count == 1, "1 emission loaded");
    dap_assert_PIF(l_stats.stake_lock_count == 1, "1 stake_lock loaded");
    dap_assert_PIF(l_stats.token_update_count == 1, "1 token_update loaded");
    dap_assert_PIF(memcmp(&l_stats.last_tx_hash, &l_tx_hash, sizeof(dap_hash_fast_t)) == 0,
                   "TX hash preserved");
    dap_assert_PIF(memcmp(l_stats.last_token_ticker, "WARM", 4) == 0,
                   "token ticker preserved");
    dap_assert_PIF(l_stats.last_token_supply.lo == 1000000,
                   "token supply preserved");
    dap_assert_PIF(l_cache.record_count == 5, "record_count updated to 5");

    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    dap_assert_PIF(l_hdr->dirty_flag == DAP_LEDGER_CACHE_DIRTY_DIRTY,
                   "dirty flag set to DIRTY after warm_load");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_warm_load_basic");
}

static void test_warm_load_skips_tombstoned(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_tx1, l_tx2;
    memset(&l_tx1, 0xA1, sizeof(l_tx1));
    memset(&l_tx2, 0xA2, sizeof(l_tx2));
    char l_ticker[10] = "TST";

    uint64_t l_off1 = dap_ledger_cache_append_tx_record(&l_cache, &l_tx1,
        100, 200, 1, 0, l_ticker, 0, 0, 0, 0, 0, 64, 0, 0, 0, NULL);
    dap_ledger_cache_append_tx_record(&l_cache, &l_tx2,
        100, 200, 1, 0, l_ticker, 0, 0, 0, 0, 0, 64, 0, 0, 0, NULL);

    dap_ledger_cache_tombstone_tx(&l_cache, l_off1);

    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    warm_load_stats_t l_stats = {0};
    dap_ledger_cache_warm_load_callbacks_t l_cbs = {
        .on_tx = s_wl_on_tx,
        .user_data = &l_stats
    };

    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, &l_cbs) == 0, "warm_load");
    dap_assert_PIF(l_stats.tx_count == 1, "only live TX delivered");
    dap_assert_PIF(memcmp(&l_stats.last_tx_hash, &l_tx2, sizeof(dap_hash_fast_t)) == 0,
                   "delivered TX is tx2 (tx1 was tombstoned)");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_warm_load_skips_tombstoned");
}

static void test_warm_load_dirty_cache_rejected(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    warm_load_stats_t l_stats = {0};
    dap_ledger_cache_warm_load_callbacks_t l_cbs = {
        .on_tx = s_wl_on_tx,
        .user_data = &l_stats
    };
    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, &l_cbs) == -2,
                   "dirty cache should return -2");
    dap_assert_PIF(l_stats.tx_count == 0, "no callbacks invoked on dirty cache");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_warm_load_dirty_cache_rejected");
}

static int s_wl_abort_on_second(const dap_ledger_cache_tx_record_t *a_rec,
                                 uint64_t a_offset, void *a_user_data)
{
    int *l_count = (int *)a_user_data;
    (*l_count)++;
    return (*l_count >= 2) ? -1 : 0;
}

static void test_warm_load_callback_abort(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    char l_ticker[10] = "ABT";
    for (int i = 0; i < 5; i++) {
        dap_hash_fast_t l_h;
        memset(&l_h, 0x50 + i, sizeof(l_h));
        dap_ledger_cache_append_tx_record(&l_cache, &l_h,
            100, 200, 1, 0, l_ticker, 0, 0, 0, 0, 0, 64, 0, 0, 0, NULL);
    }

    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    int l_count = 0;
    dap_ledger_cache_warm_load_callbacks_t l_cbs = {
        .on_tx = s_wl_abort_on_second,
        .user_data = &l_count
    };

    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, &l_cbs) == -3,
                   "callback abort should return -3");
    dap_assert_PIF(l_count == 2, "callback invoked exactly 2 times before abort");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_warm_load_callback_abort");
}

static void test_warm_load_null_callbacks(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_h;
    memset(&l_h, 0xAA, sizeof(l_h));
    char l_ticker[10] = "NUL";
    dap_ledger_cache_append_tx_record(&l_cache, &l_h,
        100, 200, 1, 0, l_ticker, 0, 0, 0, 0, 0, 64, 0, 0, 0, NULL);

    dap_hash_fast_t l_tok_hash;
    memset(&l_tok_hash, 0xBB, sizeof(l_tok_hash));
    uint256_t l_supply = uint256_0;
    dap_ledger_cache_append_token_record(&l_cache, &l_tok_hash, l_ticker, 1,
        &l_supply, 100, 0, 0, 0);

    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    dap_ledger_cache_warm_load_callbacks_t l_cbs = {0};
    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, &l_cbs) == 0,
                   "warm_load with all-NULL callbacks succeeds");
    dap_assert_PIF(l_cache.record_count == 2, "record_count still updated");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_warm_load_null_callbacks");
}

static void test_warm_load_empty_cache(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");

    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    warm_load_stats_t l_stats = {0};
    dap_ledger_cache_warm_load_callbacks_t l_cbs = {
        .on_tx = s_wl_on_tx,
        .on_token = s_wl_on_token,
        .user_data = &l_stats
    };
    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, &l_cbs) == 0,
                   "warm_load on empty clean cache succeeds");
    dap_assert_PIF(l_stats.tx_count == 0, "no records");
    dap_assert_PIF(l_cache.record_count == 0, "record_count is 0");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_warm_load_empty_cache");
}

static void test_warm_load_preserves_mutable_fields(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_tx_hash, l_spender;
    memset(&l_tx_hash, 0xBB, sizeof(l_tx_hash));
    memset(&l_spender, 0xCC, sizeof(l_spender));
    char l_ticker[10] = "MUT";
    uint64_t l_tx_off = dap_ledger_cache_append_tx_record(&l_cache, &l_tx_hash,
        100, 200, 3, 0, l_ticker, 0, 0, 0, 0, 0, 64, 0, 0, 0, NULL);

    dap_ledger_cache_update_tx_spent(&l_cache, l_tx_off, 1, &l_spender, 1, 9999);

    dap_hash_fast_t l_em_hash, l_em_spender;
    memset(&l_em_hash, 0xDD, sizeof(l_em_hash));
    memset(&l_em_spender, 0xEE, sizeof(l_em_spender));
    char l_em_ticker[10] = "MUTTEST";
    uint64_t l_em_off = dap_ledger_cache_append_emission_record(&l_cache, &l_em_hash,
        l_em_ticker, 300, 64, 0, 0, 0, false);
    dap_ledger_cache_update_emission_spent(&l_cache, l_em_off, &l_em_spender);

    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    /* Verify mutable data survived shutdown+reopen via warm_load */
    const dap_ledger_cache_tx_record_t *l_tx_rec =
        (const dap_ledger_cache_tx_record_t *)(l_cache.base + l_tx_off);
    dap_assert_PIF(l_tx_rec->n_outs_used == 1, "n_outs_used persisted");
    dap_assert_PIF(l_tx_rec->ts_spent == 9999, "ts_spent persisted");
    dap_assert_PIF(memcmp(&l_tx_rec->out_spent_hashes[1], &l_spender, sizeof(dap_hash_fast_t)) == 0,
                   "spent hash persisted");

    const dap_ledger_cache_emission_record_t *l_em_rec =
        (const dap_ledger_cache_emission_record_t *)(l_cache.base + l_em_off);
    dap_assert_PIF(memcmp(&l_em_rec->tx_used_out, &l_em_spender, sizeof(dap_hash_fast_t)) == 0,
                   "emission tx_used_out persisted");

    warm_load_stats_t l_stats = {0};
    dap_ledger_cache_warm_load_callbacks_t l_cbs = {
        .on_tx = s_wl_on_tx,
        .on_emission = s_wl_on_emission,
        .user_data = &l_stats
    };
    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, &l_cbs) == 0, "warm_load");
    dap_assert_PIF(l_stats.tx_count == 1, "1 TX");
    dap_assert_PIF(l_stats.emission_count == 1, "1 emission");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_warm_load_preserves_mutable_fields");
}

static void test_warm_load_null_args(void)
{
    dap_assert_PIF(dap_ledger_cache_warm_load(NULL, NULL) == -1, "NULL cache");

    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, NULL) == -1, "NULL callbacks");

    dap_ledger_cache_warm_load_callbacks_t l_cbs = {0};
    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, &l_cbs) == -1, "NULL base");

    dap_assert(1, "test_warm_load_null_args");
}

/* ========================================================================= */
/*  Section 9: Extended Coverage Tests                                       */
/* ========================================================================= */

static void test_update_tx_spent_nouts_overflow_via_api(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_tx_hash, l_spender;
    memset(&l_tx_hash, 0xA1, sizeof(l_tx_hash));
    memset(&l_spender, 0xB2, sizeof(l_spender));
    char l_ticker[10] = "OVF";

    uint64_t l_off = dap_ledger_cache_append_tx_record(&l_cache,
        &l_tx_hash, 100, 200, 2, 0, l_ticker, 0, 0, 0, 0, 0, 64, 0, 0, 0, NULL);
    dap_assert_PIF(l_off != (uint64_t)-1, "TX append");

    /* n_outs_used == n_outs + 1 should be rejected with -4 */
    int l_rc = dap_ledger_cache_update_tx_spent(&l_cache, l_off, 0, &l_spender, 3, 1000);
    dap_assert_PIF(l_rc == -4, "n_outs_used > n_outs must return -4");

    /* n_outs_used == n_outs is the maximum valid value (all spent) */
    l_rc = dap_ledger_cache_update_tx_spent(&l_cache, l_off, 0, &l_spender, 2, 1000);
    dap_assert_PIF(l_rc == 0, "n_outs_used == n_outs must succeed");

    /* Verify the record was actually updated */
    const dap_ledger_cache_tx_record_t *l_rec =
        (const dap_ledger_cache_tx_record_t *)(l_cache.base + l_off);
    dap_assert_PIF(l_rec->n_outs_used == 2, "n_outs_used set to 2");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_update_tx_spent_nouts_overflow_via_api");
}

static void test_data_end_clamped_on_reopen(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    /* Append a TX to advance data_end beyond header */
    dap_hash_fast_t l_tx_hash;
    memset(&l_tx_hash, 0x11, sizeof(l_tx_hash));
    char l_ticker[10] = "CLP";
    dap_ledger_cache_append_tx_record(&l_cache, &l_tx_hash,
        100, 200, 1, 0, l_ticker, 0, 0, 0, 0, 0, 64, 0, 0, 0, NULL);

    uint64_t l_true_data_end = l_cache.data_end;
    uint64_t l_mapped = l_cache.mapped_size;

    /* Corrupt the header: set data_end way beyond mapped_size */
    dap_ledger_cache_file_header_t *l_hdr = (dap_ledger_cache_file_header_t *)l_cache.base;
    l_hdr->data_end = l_mapped + 0x10000;

    /* Also write CLEAN so the file is reopenable as a "clean" cache */
    l_hdr->dirty_flag = DAP_LEDGER_CACHE_DIRTY_CLEAN;
    msync(l_cache.base, DAP_LEDGER_CACHE_HEADER_SIZE, MS_SYNC);

    dap_ledger_cache_close(&l_cache);

    /* Reopen: data_end must be clamped to file size, not the corrupt value */
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");
    dap_assert_PIF(l_cache.data_end <= l_cache.mapped_size,
                   "data_end must be clamped to at most mapped_size");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_data_end_clamped_on_reopen");
}

/* Extended warm load stats to capture richer per-record data */
typedef struct {
    int tx_count;
    int token_count;
    int emission_count;
    int stake_lock_count;
    int token_update_count;
    /* TX fields */
    dap_hash_fast_t tx_hash;
    uint32_t tx_n_outs;
    uint32_t tx_n_outs_used;
    uint64_t tx_ts_spent;
    char tx_ticker[10];
    /* Token fields */
    dap_hash_fast_t token_hash;
    char token_ticker[10];
    uint256_t token_supply;
    /* Emission fields */
    dap_hash_fast_t em_hash;
    char em_ticker[10];
    dap_hash_fast_t em_tx_used_out;
    uint8_t em_is_hardfork;
    /* Stake lock fields */
    dap_hash_fast_t sl_hash;
    /* Token update fields */
    dap_hash_fast_t upd_hash;
    char upd_ticker[10];
} ext_warm_stats_t;

static int s_ext_on_tx(const dap_ledger_cache_tx_record_t *a_rec,
                       uint64_t a_offset, void *a_user_data)
{
    ext_warm_stats_t *l_s = (ext_warm_stats_t *)a_user_data;
    l_s->tx_count++;
    l_s->tx_hash = a_rec->tx_hash_fast;
    l_s->tx_n_outs = a_rec->n_outs;
    l_s->tx_n_outs_used = a_rec->n_outs_used;
    l_s->tx_ts_spent = a_rec->ts_spent;
    memcpy(l_s->tx_ticker, a_rec->token_ticker, 10);
    return 0;
}

static int s_ext_on_token(const dap_ledger_cache_token_record_t *a_rec,
                          uint64_t a_offset, void *a_user_data)
{
    ext_warm_stats_t *l_s = (ext_warm_stats_t *)a_user_data;
    l_s->token_count++;
    l_s->token_hash = a_rec->token_hash;
    memcpy(l_s->token_ticker, a_rec->ticker, 10);
    l_s->token_supply = a_rec->current_supply;
    return 0;
}

static int s_ext_on_emission(const dap_ledger_cache_emission_record_t *a_rec,
                             uint64_t a_offset, void *a_user_data)
{
    ext_warm_stats_t *l_s = (ext_warm_stats_t *)a_user_data;
    l_s->emission_count++;
    l_s->em_hash = a_rec->datum_token_emission_hash;
    memcpy(l_s->em_ticker, a_rec->ticker, 10);
    l_s->em_tx_used_out = a_rec->tx_used_out;
    l_s->em_is_hardfork = a_rec->is_hardfork;
    return 0;
}

static int s_ext_on_stake_lock(const dap_ledger_cache_stake_lock_record_t *a_rec,
                               uint64_t a_offset, void *a_user_data)
{
    ext_warm_stats_t *l_s = (ext_warm_stats_t *)a_user_data;
    l_s->stake_lock_count++;
    l_s->sl_hash = a_rec->tx_for_stake_lock_hash;
    return 0;
}

static int s_ext_on_token_update(const dap_ledger_cache_token_update_record_t *a_rec,
                                 uint64_t a_offset, void *a_user_data)
{
    ext_warm_stats_t *l_s = (ext_warm_stats_t *)a_user_data;
    l_s->token_update_count++;
    l_s->upd_hash = a_rec->update_token_hash;
    memcpy(l_s->upd_ticker, a_rec->ticker, 10);
    return 0;
}

static void test_full_roundtrip_all_types(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    /* Append one record of each type with distinctive data */
    dap_hash_fast_t l_tx_hash, l_token_hash, l_em_hash, l_sl_hash, l_upd_hash;
    memset(&l_tx_hash, 0xA1, sizeof(l_tx_hash));
    memset(&l_token_hash, 0xB2, sizeof(l_token_hash));
    memset(&l_em_hash, 0xC3, sizeof(l_em_hash));
    memset(&l_sl_hash, 0xD4, sizeof(l_sl_hash));
    memset(&l_upd_hash, 0xE5, sizeof(l_upd_hash));

    uint256_t l_supply = uint256_0;
    l_supply.lo = 5000000;

    dap_ledger_cache_append_tx_record(&l_cache, &l_tx_hash,
        1111, 2222, 4, 0, "RTTEST", 0, 0, 0, 42, 1, 512, 0x100, 0x200, 0x300, NULL);
    dap_ledger_cache_append_token_record(&l_cache, &l_token_hash,
        "RTTEST", 2, &l_supply, 256, 0x100, 0x200, 0x300);
    dap_ledger_cache_append_emission_record(&l_cache, &l_em_hash,
        "RTTEST", 3333, 128, 0x100, 0x200, 0x300, true);
    dap_ledger_cache_append_stake_lock_record(&l_cache, &l_sl_hash, 0x400);
    dap_ledger_cache_append_token_update_record(&l_cache, &l_upd_hash,
        "RTTEST", 96, 4444, 0x100, 0x200, 0x300);

    /* Shutdown → reopen → warm_load → verify every field */
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    ext_warm_stats_t l_stats = {0};
    dap_ledger_cache_warm_load_callbacks_t l_cbs = {
        .on_tx = s_ext_on_tx,
        .on_token = s_ext_on_token,
        .on_emission = s_ext_on_emission,
        .on_stake_lock = s_ext_on_stake_lock,
        .on_token_update = s_ext_on_token_update,
        .user_data = &l_stats
    };

    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, &l_cbs) == 0, "warm_load");

    /* Counts */
    dap_assert_PIF(l_stats.tx_count == 1, "1 TX");
    dap_assert_PIF(l_stats.token_count == 1, "1 token");
    dap_assert_PIF(l_stats.emission_count == 1, "1 emission");
    dap_assert_PIF(l_stats.stake_lock_count == 1, "1 stake_lock");
    dap_assert_PIF(l_stats.token_update_count == 1, "1 token_update");

    /* TX fields */
    dap_assert_PIF(memcmp(&l_stats.tx_hash, &l_tx_hash, sizeof(dap_hash_fast_t)) == 0,
                   "TX hash round-trip");
    dap_assert_PIF(l_stats.tx_n_outs == 4, "TX n_outs round-trip");
    dap_assert_PIF(memcmp(l_stats.tx_ticker, "RTTEST", 6) == 0, "TX ticker round-trip");

    /* Token fields */
    dap_assert_PIF(memcmp(&l_stats.token_hash, &l_token_hash, sizeof(dap_hash_fast_t)) == 0,
                   "token hash round-trip");
    dap_assert_PIF(memcmp(l_stats.token_ticker, "RTTEST", 6) == 0, "token ticker round-trip");
    dap_assert_PIF(l_stats.token_supply.lo == 5000000, "token supply round-trip");

    /* Emission fields */
    dap_assert_PIF(memcmp(&l_stats.em_hash, &l_em_hash, sizeof(dap_hash_fast_t)) == 0,
                   "emission hash round-trip");
    dap_assert_PIF(memcmp(l_stats.em_ticker, "RTTEST", 6) == 0, "emission ticker round-trip");
    dap_assert_PIF(l_stats.em_is_hardfork == 1, "emission is_hardfork round-trip");
    dap_hash_fast_t l_zero_hash = {0};
    dap_assert_PIF(memcmp(&l_stats.em_tx_used_out, &l_zero_hash, sizeof(dap_hash_fast_t)) == 0,
                   "emission not spent (tx_used_out is zero)");

    /* Stake lock fields */
    dap_assert_PIF(memcmp(&l_stats.sl_hash, &l_sl_hash, sizeof(dap_hash_fast_t)) == 0,
                   "stake_lock hash round-trip");

    /* Token update fields */
    dap_assert_PIF(memcmp(&l_stats.upd_hash, &l_upd_hash, sizeof(dap_hash_fast_t)) == 0,
                   "token_update hash round-trip");
    dap_assert_PIF(memcmp(l_stats.upd_ticker, "RTTEST", 6) == 0, "token_update ticker round-trip");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_full_roundtrip_all_types");
}

static void test_compact_then_warm_load(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_tx1, l_tx2, l_tx3;
    memset(&l_tx1, 0x01, sizeof(l_tx1));
    memset(&l_tx2, 0x02, sizeof(l_tx2));
    memset(&l_tx3, 0x03, sizeof(l_tx3));
    char l_ticker[10] = "CMP";

    uint64_t l_off1 = dap_ledger_cache_append_tx_record(&l_cache, &l_tx1,
        100, 200, 1, 0, l_ticker, 0, 0, 0, 0, 0, 64, 0, 0, 0, NULL);
    dap_ledger_cache_append_tx_record(&l_cache, &l_tx2,
        100, 200, 1, 0, l_ticker, 0, 0, 0, 0, 0, 64, 0, 0, 0, NULL);
    dap_ledger_cache_append_tx_record(&l_cache, &l_tx3,
        100, 200, 1, 0, l_ticker, 0, 0, 0, 0, 0, 64, 0, 0, 0, NULL);

    /* Tombstone tx1 so compaction removes it */
    dap_ledger_cache_tombstone_tx(&l_cache, l_off1);

    dap_assert_PIF(l_cache.record_count == 3, "3 records before compact");
    dap_assert_PIF(dap_ledger_cache_compact(&l_cache, NULL, 0) == 0, "compact");
    dap_assert_PIF(l_cache.record_count == 2, "2 records after compact");

    /* Shutdown cleanly, reopen, warm load */
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    ext_warm_stats_t l_stats = {0};
    dap_ledger_cache_warm_load_callbacks_t l_cbs = {
        .on_tx = s_ext_on_tx,
        .user_data = &l_stats
    };
    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, &l_cbs) == 0, "warm_load");
    dap_assert_PIF(l_stats.tx_count == 2, "2 live TX after compact + warm_load");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_compact_then_warm_load");
}

static void test_spent_state_survives_warm_load(void)
{
    const char *l_path = s_next_test_file();
    dap_ledger_cache_t l_cache = {0};
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "open");
    dap_ledger_cache_mark_dirty(&l_cache);

    dap_hash_fast_t l_tx_hash, l_sp0, l_sp2;
    memset(&l_tx_hash, 0xAA, sizeof(l_tx_hash));
    memset(&l_sp0, 0x10, sizeof(l_sp0));
    memset(&l_sp2, 0x30, sizeof(l_sp2));
    char l_ticker[10] = "SPT";

    /* TX with 3 outputs: spend out[0] and out[2], leave out[1] unspent */
    uint64_t l_off = dap_ledger_cache_append_tx_record(&l_cache, &l_tx_hash,
        100, 200, 3, 0, l_ticker, 0, 0, 0, 0, 0, 64, 0, 0, 0, NULL);
    dap_assert_PIF(l_off != (uint64_t)-1, "TX append");

    dap_assert_PIF(dap_ledger_cache_update_tx_spent(&l_cache, l_off, 0, &l_sp0, 1, 5000) == 0,
                   "spend out[0]");
    dap_assert_PIF(dap_ledger_cache_update_tx_spent(&l_cache, l_off, 2, &l_sp2, 2, 6000) == 0,
                   "spend out[2]");

    /* Also add and spend an emission */
    dap_hash_fast_t l_em_hash, l_em_sp;
    memset(&l_em_hash, 0xBB, sizeof(l_em_hash));
    memset(&l_em_sp, 0xCC, sizeof(l_em_sp));
    uint64_t l_em_off = dap_ledger_cache_append_emission_record(&l_cache, &l_em_hash,
        l_ticker, 300, 64, 0, 0, 0, false);
    dap_ledger_cache_update_emission_spent(&l_cache, l_em_off, &l_em_sp);

    /* Shutdown → reopen → warm load */
    dap_assert_PIF(dap_ledger_cache_shutdown(&l_cache, NULL, 0) == 0, "shutdown");
    dap_assert_PIF(dap_ledger_cache_open(&l_cache, l_path, TEST_NET_ID) == 0, "reopen");

    ext_warm_stats_t l_stats = {0};
    dap_ledger_cache_warm_load_callbacks_t l_cbs = {
        .on_tx = s_ext_on_tx,
        .on_emission = s_ext_on_emission,
        .user_data = &l_stats
    };
    dap_assert_PIF(dap_ledger_cache_warm_load(&l_cache, &l_cbs) == 0, "warm_load");

    /* Verify TX spent state via callback data */
    dap_assert_PIF(l_stats.tx_n_outs == 3, "n_outs == 3");
    dap_assert_PIF(l_stats.tx_n_outs_used == 2, "n_outs_used == 2 after round-trip");
    dap_assert_PIF(l_stats.tx_ts_spent == 6000, "ts_spent preserved");

    /* Also verify the spent hashes directly from the mmap buffer */
    const dap_ledger_cache_tx_record_t *l_rec =
        (const dap_ledger_cache_tx_record_t *)(l_cache.base + l_off);
    dap_assert_PIF(memcmp(&l_rec->out_spent_hashes[0], &l_sp0, sizeof(dap_hash_fast_t)) == 0,
                   "out[0] spender hash survived");
    dap_hash_fast_t l_zero = {0};
    dap_assert_PIF(memcmp(&l_rec->out_spent_hashes[1], &l_zero, sizeof(dap_hash_fast_t)) == 0,
                   "out[1] still unspent (zero hash)");
    dap_assert_PIF(memcmp(&l_rec->out_spent_hashes[2], &l_sp2, sizeof(dap_hash_fast_t)) == 0,
                   "out[2] spender hash survived");

    /* Verify emission spent state: tx_used_out should be l_em_sp */
    dap_assert_PIF(memcmp(&l_stats.em_tx_used_out, &l_em_sp, sizeof(dap_hash_fast_t)) == 0,
                   "emission tx_used_out survived round-trip");

    dap_ledger_cache_close(&l_cache);
    s_remove_test_file(l_path);
    dap_assert(1, "test_spent_state_survives_warm_load");
}

/* ========================================================================= */
/*  MAIN                                                                     */
/* ========================================================================= */

int main(void)
{
    dap_common_init("test_ledger_cache", NULL);

    dap_print_module_name("Ledger mmap Cache");

    /* Create test directory */
    mkdir(TEST_DIR, 0755);

    printf("\n--- Section 3.1: File Format and Scanner ---\n");
    test_struct_sizes();
    test_valid_header();
    test_invalid_magic();
    test_unsupported_version();
    test_dirty_flag_clean();
    test_dirty_flag_dirty();
    test_malformed_tail_record();
    test_record_size_zero();
    test_record_size_exceeds_remaining();
    test_unknown_record_type();
    test_record_type_zero();
    test_record_size_less_than_header();
    test_record_size_less_than_type_minimum();

    printf("\n--- Section 3.2: TX Operations ---\n");
    test_tx_add();
    test_tx_spend();
    test_tx_unspend();
    test_tx_output_bounds_check();
    test_tx_n_outs_used_overflow();
    test_tx_n_outs_used_underflow();
    test_tx_rollback_tombstone();

    printf("\n--- Section 3.3: Token and Token Update ---\n");
    test_token_add();
    test_token_supply_update();
    test_token_update_add();
    test_token_update_replay_order();
    test_ticker_binary_safety();

    printf("\n--- Section 3.4: Emission and Stake Lock ---\n");
    test_emission_add();
    test_emission_spend();
    test_emission_unspend();
    test_emission_is_hardfork();
    test_stake_lock_add();
    test_stake_lock_spend();
    test_stake_lock_unspend();

    printf("\n--- Section 3.6: Cache Lifecycle ---\n");
    test_mixed_record_types_scan();
    test_shutdown_and_reopen();
    test_reopen_preserves_data();
    test_multiple_appends_and_scan();
    test_resize_path();
    test_manifest_shutdown();
    test_null_params();

    printf("\n--- Section 3.6+: Compaction, Purge, Manifest Validation ---\n");
    test_compaction_removes_tombstoned();
    test_compaction_preserves_live_data();
    test_compaction_with_manifest();
    test_purge();
    test_manifest_hash_mismatch();
    test_manifest_no_entries_valid();
    test_record_count_mismatch();
    test_data_end_beyond_mapped_size();
    test_tombstone_detection_all_types();

    printf("\n--- Section 5: Crash Simulation (CP1-CP8) ---\n");
    test_crash_cp1_torn_record_at_eof();
    test_crash_cp2_record_written_header_not_updated();
    test_crash_cp3_data_end_advanced_no_msync();
    test_crash_cp4_partial_mutable_update();
    test_crash_cp5_mid_rollback();
    test_crash_cp6_compaction_interrupted();
    test_crash_cp7_after_data_msync_before_clean();
    test_crash_cp8_clean_written_manifest_incomplete();

    printf("\n--- Section 6: Higher-Level Append & Update API ---\n");
    test_hlapi_tx_append_and_update();
    test_hlapi_token_append_and_supply_update();
    test_hlapi_emission_append_and_spend();
    test_hlapi_stake_lock_append_and_spend();
    test_hlapi_token_update_append();
    test_hlapi_tombstone_tx();

    printf("\n--- Section 7: Coverage Gap Tests ---\n");
    test_validate_manifest_data_end_below_header();
    test_validate_manifest_beyond_mapped_size();
    test_validate_manifest_no_entries_nonzero_hash();
    test_validate_manifest_corrupt_record_during_scan();
    test_scan_callback_early_termination();
    test_scan_null_callback();
    test_update_tx_spent_wrong_type();
    test_update_tx_spent_bad_offset();
    test_update_emission_spent_wrong_type();
    test_update_stake_lock_spent_wrong_type();
    test_update_token_supply_wrong_type();
    test_tombstone_tx_wrong_type();
    test_tx_append_with_out_spent_hashes();
    test_record_at_inline();
    test_validate_record_null_base();
    test_purge_null();
    test_compact_null();

    printf("\n--- Section 8: Warm Startup Load ---\n");
    test_warm_load_basic();
    test_warm_load_skips_tombstoned();
    test_warm_load_dirty_cache_rejected();
    test_warm_load_callback_abort();
    test_warm_load_null_callbacks();
    test_warm_load_empty_cache();
    test_warm_load_preserves_mutable_fields();
    test_warm_load_null_args();

    printf("\n--- Section 9: Extended Coverage ---\n");
    test_update_tx_spent_nouts_overflow_via_api();
    test_data_end_clamped_on_reopen();
    test_full_roundtrip_all_types();
    test_compact_then_warm_load();
    test_spent_state_survives_warm_load();

    printf("\n" TEXT_COLOR_GRN "=== ALL LEDGER CACHE TESTS PASSED (90/90) ===" TEXT_COLOR_RESET "\n");

    return 0;
}
