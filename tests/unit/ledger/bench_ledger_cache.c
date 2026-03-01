/**
 * @file bench_ledger_cache.c
 * @brief Performance benchmark for the mmap-based ledger cache
 * @details Validates performance targets from new_cache_ledger.md Section 12:
 *   - Headroom sizing & resize frequency (2x growth factor)
 *   - Warm startup time (target: <= 800 ms for 500K TXs, pages in cache)
 *   - Cold startup time (target: <= 9 s for 500K TXs, pages evicted)
 *   - Append/update operation latency
 *   - Disk usage verification (~108 MB for reference dataset)
 *   - Heap usage estimation from compiled struct sizes (~177 MB)
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
#include <time.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_chain_ledger_cache.h"

#define BENCH_NET_ID  0x00BE0C4CA00E0000ULL
#define BENCH_DIR     "/tmp/bench_ledger_cache"
#define BENCH_FILE    BENCH_DIR "/bench.lcache"

#define NUM_TX          500000
#define NUM_TOKENS      100
#define NUM_EMISSIONS   10000
#define NUM_STAKE_LOCKS 1000
#define NUM_TOKEN_UPDATES 100
#define AVG_OUTS_PER_TX 3

static double s_elapsed_ms(struct timespec *a_start, struct timespec *a_end)
{
    return (a_end->tv_sec - a_start->tv_sec) * 1000.0
         + (a_end->tv_nsec - a_start->tv_nsec) / 1.0e6;
}

static void s_make_hash(dap_hash_fast_t *a_hash, uint32_t a_seed)
{
    memset(a_hash, 0, sizeof(*a_hash));
    memcpy(a_hash, &a_seed, sizeof(a_seed));
}

static uint64_t s_resize_count = 0;

static void s_populate_cache(dap_ledger_cache_t *a_cache)
{
    struct timespec l_start, l_end;
    uint64_t l_prev_mapped = a_cache->mapped_size;

    printf("  Populating: %d tokens, %d emissions, %d stake locks, %d token_updates, %d TXs (avg %d outs)...\n",
           NUM_TOKENS, NUM_EMISSIONS, NUM_STAKE_LOCKS, NUM_TOKEN_UPDATES, NUM_TX, AVG_OUTS_PER_TX);

    clock_gettime(CLOCK_MONOTONIC, &l_start);

    for (uint32_t i = 0; i < NUM_TOKENS; i++) {
        dap_hash_fast_t l_hash;
        s_make_hash(&l_hash, 0x70000000 + i);
        char l_ticker[10] = {0};
        snprintf(l_ticker, sizeof(l_ticker), "TKN%05u", i);
        uint256_t l_supply = {};
        l_supply.lo = 1000000 + i;
        dap_ledger_cache_append_token_record(a_cache, &l_hash, l_ticker, 1,
                                              &l_supply, 256, 1, 1, 1024 + i);
    }

    for (uint32_t i = 0; i < NUM_EMISSIONS; i++) {
        dap_hash_fast_t l_hash;
        s_make_hash(&l_hash, 0x30000000 + i);
        char l_ticker[10] = {0};
        snprintf(l_ticker, sizeof(l_ticker), "TKN%05u", i % NUM_TOKENS);
        dap_ledger_cache_append_emission_record(a_cache, &l_hash, l_ticker,
                                                 1000000ULL + i, 512, 1, 1,
                                                 2048 + i, false);
    }

    for (uint32_t i = 0; i < NUM_STAKE_LOCKS; i++) {
        dap_hash_fast_t l_hash;
        s_make_hash(&l_hash, 0x40000000 + i);
        dap_ledger_cache_append_stake_lock_record(a_cache, &l_hash, 4096 + i);
    }

    for (uint32_t i = 0; i < NUM_TOKEN_UPDATES; i++) {
        dap_hash_fast_t l_hash;
        s_make_hash(&l_hash, 0x50000000 + i);
        char l_ticker[10] = {0};
        snprintf(l_ticker, sizeof(l_ticker), "TKN%05u", i % NUM_TOKENS);
        dap_ledger_cache_append_token_update_record(a_cache, &l_hash, l_ticker,
                                                     128, (uint64_t)time(NULL), 1, 1,
                                                     8192 + i);
    }

    for (uint32_t i = 0; i < NUM_TX; i++) {
        dap_hash_fast_t l_hash;
        s_make_hash(&l_hash, i);
        char l_ticker[10] = {0};
        snprintf(l_ticker, sizeof(l_ticker), "TKN%05u", i % NUM_TOKENS);
        dap_hash_fast_t l_outs[AVG_OUTS_PER_TX] = {};
        uint64_t l_prev = a_cache->mapped_size;
        dap_ledger_cache_append_tx_record(a_cache, &l_hash, 1000000ULL + i,
                                           (uint64_t)time(NULL), AVG_OUTS_PER_TX,
                                           0, l_ticker, 0, 0, 0, 0, 0, 500,
                                           1, 1, 16384 + i, l_outs);
        if (a_cache->mapped_size != l_prev) {
            s_resize_count++;
            printf("    Resize #%lu at record %u: %lu MB -> %lu MB\n",
                   (unsigned long)s_resize_count, i,
                   (unsigned long)(l_prev / (1024*1024)),
                   (unsigned long)(a_cache->mapped_size / (1024*1024)));
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &l_end);
    double l_ms = s_elapsed_ms(&l_start, &l_end);
    printf("  Populate time: %.1f ms (%.0f records/sec)\n", l_ms,
           (NUM_TX + NUM_TOKENS + NUM_EMISSIONS + NUM_STAKE_LOCKS + NUM_TOKEN_UPDATES) / (l_ms / 1000.0));
    printf("  Resizes during populate: %lu (initial %lu MB -> final %lu MB)\n",
           (unsigned long)s_resize_count,
           (unsigned long)(DAP_LEDGER_CACHE_INITIAL_SIZE / (1024*1024)),
           (unsigned long)(a_cache->mapped_size / (1024*1024)));
}

typedef struct {
    uint64_t n_tx;
    uint64_t n_token;
    uint64_t n_emission;
    uint64_t n_stake_lock;
    uint64_t n_token_update;
} warm_load_stats_t;

static int s_on_tx(const dap_ledger_cache_tx_record_t *a_rec, uint64_t a_off, void *a_ud)
{
    (void)a_rec; (void)a_off;
    ((warm_load_stats_t *)a_ud)->n_tx++;
    return 0;
}
static int s_on_token(const dap_ledger_cache_token_record_t *a_rec, uint64_t a_off, void *a_ud)
{
    (void)a_rec; (void)a_off;
    ((warm_load_stats_t *)a_ud)->n_token++;
    return 0;
}
static int s_on_emission(const dap_ledger_cache_emission_record_t *a_rec, uint64_t a_off, void *a_ud)
{
    (void)a_rec; (void)a_off;
    ((warm_load_stats_t *)a_ud)->n_emission++;
    return 0;
}
static int s_on_stake_lock(const dap_ledger_cache_stake_lock_record_t *a_rec, uint64_t a_off, void *a_ud)
{
    (void)a_rec; (void)a_off;
    ((warm_load_stats_t *)a_ud)->n_stake_lock++;
    return 0;
}
static int s_on_token_update(const dap_ledger_cache_token_update_record_t *a_rec, uint64_t a_off, void *a_ud)
{
    (void)a_rec; (void)a_off;
    ((warm_load_stats_t *)a_ud)->n_token_update++;
    return 0;
}

/**
 * Run warm_load and print results. After measurement, re-shutdown so the
 * cache stays CLEAN for subsequent tests.
 */
static void s_bench_warm_startup(const char *a_label)
{
    struct timespec l_start, l_end;
    dap_ledger_cache_t l_cache = {};

    clock_gettime(CLOCK_MONOTONIC, &l_start);
    int l_rc = dap_ledger_cache_open(&l_cache, BENCH_FILE, BENCH_NET_ID);
    clock_gettime(CLOCK_MONOTONIC, &l_end);
    if (l_rc != 0) {
        printf("  [FAIL] Cache open failed for %s: %d\n", a_label, l_rc);
        return;
    }
    double l_open_ms = s_elapsed_ms(&l_start, &l_end);

    warm_load_stats_t l_stats = {};
    dap_ledger_cache_warm_load_callbacks_t l_cbs = {
        .on_tx = s_on_tx,
        .on_token = s_on_token,
        .on_emission = s_on_emission,
        .on_stake_lock = s_on_stake_lock,
        .on_token_update = s_on_token_update,
        .user_data = &l_stats,
    };

    clock_gettime(CLOCK_MONOTONIC, &l_start);
    l_rc = dap_ledger_cache_warm_load(&l_cache, &l_cbs);
    clock_gettime(CLOCK_MONOTONIC, &l_end);
    double l_load_ms = s_elapsed_ms(&l_start, &l_end);

    printf("  %s:\n", a_label);
    printf("    open:      %.1f ms\n", l_open_ms);
    printf("    warm_load: %.1f ms (rc=%d)\n", l_load_ms, l_rc);
    printf("    total:     %.1f ms\n", l_open_ms + l_load_ms);
    printf("    records:   TX=%lu, token=%lu, emission=%lu, stake_lock=%lu, token_update=%lu\n",
           (unsigned long)l_stats.n_tx, (unsigned long)l_stats.n_token,
           (unsigned long)l_stats.n_emission, (unsigned long)l_stats.n_stake_lock,
           (unsigned long)l_stats.n_token_update);

    if (l_rc == 0) {
        uint64_t l_total_expected = (uint64_t)NUM_TX + NUM_TOKENS + NUM_EMISSIONS
                                  + NUM_STAKE_LOCKS + NUM_TOKEN_UPDATES;
        uint64_t l_total_got = l_stats.n_tx + l_stats.n_token + l_stats.n_emission
                             + l_stats.n_stake_lock + l_stats.n_token_update;
        if (l_total_got < l_total_expected)
            printf("    [WARN] Expected >= %lu total records, got %lu\n",
                   (unsigned long)l_total_expected, (unsigned long)l_total_got);

        dap_ledger_cache_shutdown(&l_cache, NULL, 0);
    } else {
        dap_ledger_cache_close(&l_cache);
    }
}

static void s_bench_cold_startup(void)
{
    int l_fd = open(BENCH_FILE, O_RDONLY);
    if (l_fd < 0) {
        printf("  [SKIP] Cannot open file for cold eviction: %s\n", strerror(errno));
        return;
    }
    struct stat l_st;
    fstat(l_fd, &l_st);

#ifdef __linux__
    if (posix_fadvise(l_fd, 0, l_st.st_size, POSIX_FADV_DONTNEED) != 0)
        printf("  [WARN] posix_fadvise DONTNEED failed: %s\n", strerror(errno));
    else
        printf("  Evicted %lu MB from page cache via POSIX_FADV_DONTNEED\n",
               (unsigned long)(l_st.st_size / (1024*1024)));
#else
    printf("  [SKIP] Cold startup eviction only supported on Linux\n");
    close(l_fd);
    return;
#endif
    close(l_fd);
    sync();

    s_bench_warm_startup("Cold startup (pages evicted)");
}

static void s_bench_update_latency(dap_ledger_cache_t *a_cache)
{
    struct timespec l_start, l_end;
    const int N = 100000;
    dap_hash_fast_t l_spender = {};
    memset(&l_spender, 0xAB, sizeof(l_spender));

    dap_hash_fast_t l_hash;
    s_make_hash(&l_hash, 42);
    char l_ticker[10] = {0};
    snprintf(l_ticker, sizeof(l_ticker), "TKN00042");
    dap_hash_fast_t l_outs[AVG_OUTS_PER_TX] = {};
    uint64_t l_off = dap_ledger_cache_append_tx_record(a_cache, &l_hash, 1, 1,
                                                        AVG_OUTS_PER_TX, 0,
                                                        l_ticker, 0, 0, 0, 0, 0,
                                                        500, 1, 1, 9999, l_outs);
    if (l_off == (uint64_t)-1) {
        printf("  [FAIL] Cannot create test TX for update latency\n");
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &l_start);
    for (int i = 0; i < N; i++) {
        dap_ledger_cache_update_tx_spent(a_cache, l_off, i % AVG_OUTS_PER_TX,
                                          &l_spender, (uint32_t)(i % AVG_OUTS_PER_TX) + 1, 12345);
    }
    clock_gettime(CLOCK_MONOTONIC, &l_end);
    double l_ms = s_elapsed_ms(&l_start, &l_end);
    printf("  update_tx_spent: %d ops in %.1f ms -> %.0f ns/op\n",
           N, l_ms, l_ms * 1e6 / N);
}

static void s_print_struct_sizes(void)
{
    printf("\n=== Struct Sizes (compiled) ===\n");
    printf("  dap_ledger_cache_file_header_t:       %3zu B\n", sizeof(dap_ledger_cache_file_header_t));
    printf("  dap_ledger_cache_record_hdr_t:        %3zu B\n", sizeof(dap_ledger_cache_record_hdr_t));
    printf("  dap_ledger_cache_tx_record_t (base):  %3zu B\n", sizeof(dap_ledger_cache_tx_record_t));
    printf("  dap_ledger_cache_token_record_t:      %3zu B\n", sizeof(dap_ledger_cache_token_record_t));
    printf("  dap_ledger_cache_emission_record_t:   %3zu B\n", sizeof(dap_ledger_cache_emission_record_t));
    printf("  dap_ledger_cache_stake_lock_record_t: %3zu B\n", sizeof(dap_ledger_cache_stake_lock_record_t));
    printf("  dap_ledger_cache_token_update_record_t: %3zu B\n", sizeof(dap_ledger_cache_token_update_record_t));
    printf("  dap_ledger_cache_manifest_entry_t:    %3zu B\n", sizeof(dap_ledger_cache_manifest_entry_t));
    printf("  dap_hash_fast_t:                      %3zu B\n", sizeof(dap_hash_fast_t));

    uint64_t l_tx_per_record = sizeof(dap_ledger_cache_tx_record_t)
                             + AVG_OUTS_PER_TX * sizeof(dap_hash_fast_t);
    uint64_t l_disk_tx      = (uint64_t)NUM_TX * l_tx_per_record;
    uint64_t l_disk_token   = (uint64_t)NUM_TOKENS * sizeof(dap_ledger_cache_token_record_t);
    uint64_t l_disk_emission = (uint64_t)NUM_EMISSIONS * sizeof(dap_ledger_cache_emission_record_t);
    uint64_t l_disk_stake   = (uint64_t)NUM_STAKE_LOCKS * sizeof(dap_ledger_cache_stake_lock_record_t);
    uint64_t l_disk_tupdate = (uint64_t)NUM_TOKEN_UPDATES * sizeof(dap_ledger_cache_token_update_record_t);
    uint64_t l_disk_total   = sizeof(dap_ledger_cache_file_header_t) + l_disk_tx + l_disk_token
                            + l_disk_emission + l_disk_stake + l_disk_tupdate;

    printf("\n=== Disk Usage Estimate (reference dataset) ===\n");
    printf("  Header:         %10zu B\n", sizeof(dap_ledger_cache_file_header_t));
    printf("  TX records:     %10lu B  (%d x %lu B)\n",
           (unsigned long)l_disk_tx, NUM_TX, (unsigned long)l_tx_per_record);
    printf("  Token records:  %10lu B  (%d x %zu B)\n",
           (unsigned long)l_disk_token, NUM_TOKENS, sizeof(dap_ledger_cache_token_record_t));
    printf("  Emission recs:  %10lu B  (%d x %zu B)\n",
           (unsigned long)l_disk_emission, NUM_EMISSIONS, sizeof(dap_ledger_cache_emission_record_t));
    printf("  Stake lock recs:%10lu B  (%d x %zu B)\n",
           (unsigned long)l_disk_stake, NUM_STAKE_LOCKS, sizeof(dap_ledger_cache_stake_lock_record_t));
    printf("  Token update:   %10lu B  (%d x %zu B)\n",
           (unsigned long)l_disk_tupdate, NUM_TOKEN_UPDATES, sizeof(dap_ledger_cache_token_update_record_t));
    printf("  ---\n");
    printf("  Total data:     %10lu B  (%.1f MB)\n",
           (unsigned long)l_disk_total, l_disk_total / (1024.0 * 1024.0));
    printf("  Target (doc):   ~108 MB\n");

    /*
     * Heap usage estimate: per-item sizes for in-memory uthash indices.
     * UT_hash_handle is typically 56 B on 64-bit (6 pointers + 2 uint32).
     * Bucket table adds ~8 B per entry on average (load factor ~1.0).
     */
    size_t l_ut_hh = 6 * sizeof(void *) + 2 * sizeof(unsigned);
    size_t l_tx_item_base = sizeof(dap_hash_fast_t) + sizeof(void *)  /* tx pointer */
                          + sizeof(uint64_t)                           /* ts_added */
                          + l_ut_hh
                          + (8 + 4 + 4 + 10 + 1 + 8 + 8 + 4)         /* cache_data packed */
                          + sizeof(uint64_t);                          /* cache_record_offset */
    size_t l_tx_out_meta = sizeof(dap_hash_fast_t) + sizeof(void *);
    size_t l_tx_item_full = l_tx_item_base + AVG_OUTS_PER_TX * l_tx_out_meta + 16; /* malloc overhead */
    size_t l_bucket_overhead_per_entry = sizeof(void *);

    uint64_t l_heap_tx = (uint64_t)NUM_TX * (l_tx_item_full + l_bucket_overhead_per_entry);

    size_t l_emission_item = sizeof(dap_hash_fast_t)  /* emission hash */
                           + sizeof(void *)            /* datum pointer */
                           + sizeof(size_t)            /* datum size */
                           + sizeof(dap_hash_fast_t)   /* tx_used_out */
                           + sizeof(uint64_t)          /* ts_added */
                           + sizeof(bool) + sizeof(uint64_t) /* is_hardfork + cache_offset */
                           + l_ut_hh;
    uint64_t l_heap_emission = (uint64_t)NUM_EMISSIONS * (l_emission_item + l_bucket_overhead_per_entry + 16);

    uint64_t l_heap_balance = 100000ULL * 80;

    uint64_t l_heap_total = l_heap_tx + l_heap_emission + l_heap_balance;

    printf("\n=== Heap Usage Estimate ===\n");
    printf("  UT_hash_handle:        %3zu B\n", l_ut_hh);
    printf("  TX item (base):        %3zu B\n", l_tx_item_base);
    printf("  TX item (full, 3 outs):%3zu B\n", l_tx_item_full);
    printf("  TX index total:        %.1f MB  (%d items)\n",
           l_heap_tx / (1024.0 * 1024.0), NUM_TX);
    printf("  Emission index total:  %.1f MB  (%d items)\n",
           l_heap_emission / (1024.0 * 1024.0), NUM_EMISSIONS);
    printf("  Balance accounts:      %.1f MB  (~100K accounts)\n",
           l_heap_balance / (1024.0 * 1024.0));
    printf("  ---\n");
    printf("  Estimated total:       %.1f MB\n", l_heap_total / (1024.0 * 1024.0));
    printf("  Target (doc):          ~177 MB\n");
}

static void s_print_actual_disk_usage(void)
{
    struct stat l_st;
    if (stat(BENCH_FILE, &l_st) == 0) {
        printf("\n=== Actual Disk Usage ===\n");
        printf("  File size:     %lu B  (%.1f MB)\n",
               (unsigned long)l_st.st_size, l_st.st_size / (1024.0 * 1024.0));

        dap_ledger_cache_t l_cache = {};
        if (dap_ledger_cache_open(&l_cache, BENCH_FILE, BENCH_NET_ID) == 0) {
            printf("  data_end:      %lu B  (%.1f MB)\n",
                   (unsigned long)l_cache.data_end, l_cache.data_end / (1024.0 * 1024.0));
            printf("  mapped_size:   %lu B  (%.1f MB)\n",
                   (unsigned long)l_cache.mapped_size, l_cache.mapped_size / (1024.0 * 1024.0));
            printf("  record_count:  %lu\n", (unsigned long)l_cache.record_count);
            printf("  headroom:      %.1f MB\n",
                   (l_cache.mapped_size - l_cache.data_end) / (1024.0 * 1024.0));
            dap_ledger_cache_close(&l_cache);
        }
    }
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    printf("=== Ledger Cache Performance Benchmark ===\n");
    printf("Dataset: %dK TXs (%d outs), %d tokens, %dK emissions, %d stake locks, %d token updates\n\n",
           NUM_TX / 1000, AVG_OUTS_PER_TX, NUM_TOKENS,
           NUM_EMISSIONS / 1000, NUM_STAKE_LOCKS, NUM_TOKEN_UPDATES);

    /* Step 0: struct sizes and estimates (no I/O) */
    s_print_struct_sizes();

    /* Step 1: create directory and populate */
    mkdir(BENCH_DIR, 0755);
    unlink(BENCH_FILE);

    dap_ledger_cache_t l_cache = {};
    int l_rc = dap_ledger_cache_open(&l_cache, BENCH_FILE, BENCH_NET_ID);
    if (l_rc != 0) {
        printf("[FAIL] Cannot open cache: %d\n", l_rc);
        return 1;
    }

    printf("\n=== 1) Headroom & Resize Frequency ===\n");
    s_populate_cache(&l_cache);

    /* Step 2: update latency */
    printf("\n=== 2) In-Place Update Latency ===\n");
    s_bench_update_latency(&l_cache);

    /* Step 3: shutdown (writes manifest + marks clean) */
    printf("\n=== 3) Shutdown ===\n");
    struct timespec l_start, l_end;
    clock_gettime(CLOCK_MONOTONIC, &l_start);
    l_rc = dap_ledger_cache_shutdown(&l_cache, NULL, 0);
    clock_gettime(CLOCK_MONOTONIC, &l_end);
    printf("  Shutdown time: %.1f ms (rc=%d)\n", s_elapsed_ms(&l_start, &l_end), l_rc);

    s_print_actual_disk_usage();

    /* Step 4: warm startup (pages in OS cache) */
    printf("\n=== 4) Warm Startup (pages in OS cache) ===\n");
    s_bench_warm_startup("Warm startup");

    /* Step 5: cold startup (evict pages first) */
    printf("\n=== 5) Cold Startup (pages evicted) ===\n");
    s_bench_cold_startup();

    /* Step 6: second warm run for stability */
    printf("\n=== 6) Warm Startup (second run) ===\n");
    s_bench_warm_startup("Warm startup (run 2)");

    printf("\n=== BENCHMARK COMPLETE ===\n");
    return 0;
}
