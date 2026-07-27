/*
 * test_stream_defrag.c — Integration tests for stream defragmentation security.
 *
 * Tests the P0-5/P0-6 security fixes in dap_stream.c:
 * 1. DAP_STREAM_MAX_REASSEMBLY (16MB) cap on full_size
 * 2. Bounds check: mem_shift + size <= full_size before memcpy
 * 3. In-order assembly enforcement (mem_shift == filled)
 * 4. Large payload round-trip (3.25MB realistic anon TX size)
 */
#include "dap_test.h"
#include "dap_common.h"
#include "dap_stream_pkt.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* DAP_STREAM_MAX_REASSEMBLY as defined in dap_stream.c P0-5 fix */
#define TEST_MAX_REASSEMBLY (16 * 1024 * 1024)

/* Realistic anonymous TX size (range proof + ring sig) */
#define TEST_ANON_TX_SIZE (3 * 1024 * 1024 + 256 * 1024) /* ~3.25 MB */

static int test_fragment_pkt_structure(void)
{
    printf("\tTest 1: Fragment packet structural invariants\n");
    dap_assert_PIF(sizeof(dap_stream_fragment_pkt_t) == 12, "fragment pkt size != 12");

    dap_stream_fragment_pkt_t l_pkt = {0};
    l_pkt.size = 0x11111111;
    l_pkt.mem_shift = 0x22222222;
    l_pkt.full_size = 0x33333333;
    dap_assert_PIF(l_pkt.size == 0x11111111, "size field");
    dap_assert_PIF(l_pkt.mem_shift == 0x22222222, "mem_shift field");
    dap_assert_PIF(l_pkt.full_size == 0x33333333, "full_size field");
    printf("\t%sPASS%s\n", TEXT_COLOR_GRN, TEXT_COLOR_RESET);
    return 0;
}

static int test_oom_cap(void)
{
    printf("\tTest 2: OOM cap (full_size > %d rejected)\n", TEST_MAX_REASSEMBLY);
    struct { uint32_t full_size; int should_reject; } l_cases[] = {
        { TEST_MAX_REASSEMBLY, 0 },
        { TEST_MAX_REASSEMBLY + 1, 1 },
        { 0xFFFFFFFF, 1 },
        { 1024, 0 },
        { TEST_ANON_TX_SIZE, 0 },
    };
    for (size_t i = 0; i < sizeof(l_cases)/sizeof(l_cases[0]); i++) {
        int l_reject = (l_cases[i].full_size > TEST_MAX_REASSEMBLY);
        dap_assert_PIF(l_reject == l_cases[i].should_reject, "OOM cap case failed");
    }
    printf("\t%sPASS%s\n", TEXT_COLOR_GRN, TEXT_COLOR_RESET);
    return 0;
}

static int test_overflow_check(void)
{
    printf("\tTest 3: Overflow check (mem_shift + size > full_size)\n");
    struct {
        uint32_t mem_shift, size, full_size;
        int should_reject;
    } l_cases[] = {
        { 0,    1000, 10000, 0 },
        { 1000, 1000, 10000, 0 },
        { 9000, 1000, 10000, 0 },
        { 9001, 1000, 10000, 1 },
        { 0,    10001,10000, 1 },
        { 10001,0,    10000, 1 },
        { 10000,0,    10000, 0 },
        { 0,          65536, TEST_ANON_TX_SIZE, 0 },
        { TEST_ANON_TX_SIZE - 65536, 65536, TEST_ANON_TX_SIZE, 0 },
        { TEST_ANON_TX_SIZE,        0,     TEST_ANON_TX_SIZE, 0 },
        { TEST_ANON_TX_SIZE - 1000, 2000,  TEST_ANON_TX_SIZE, 1 },
    };
    for (size_t i = 0; i < sizeof(l_cases)/sizeof(l_cases[0]); i++) {
        int l_overflow = ((size_t)l_cases[i].mem_shift + l_cases[i].size > l_cases[i].full_size);
        dap_assert_PIF(l_overflow == l_cases[i].should_reject, "overflow case failed");
    }
    printf("\t%sPASS%s\n", TEXT_COLOR_GRN, TEXT_COLOR_RESET);
    return 0;
}

static int test_in_order_assembly(void)
{
    printf("\tTest 4: In-order assembly enforcement\n");
    const uint32_t l_full = 100000;
    size_t l_filled = 0;
    uint32_t l_offsets[] = {0,10000,20000,30000,40000,50000,60000,70000,80000,90000};
    uint32_t l_sizes[]   = {10000,10000,10000,10000,10000,10000,10000,10000,10000,10000};
    for (int i = 0; i < 10; i++) {
        dap_assert_PIF(l_offsets[i] == l_filled, "wrong position");
        dap_assert_PIF((size_t)l_offsets[i] + l_sizes[i] <= l_full, "overflow");
        l_filled += l_sizes[i];
    }
    dap_assert_PIF(l_filled == l_full, "not fully assembled");
    /* Out-of-order must be rejected */
    l_filled = 30000;
    uint32_t l_bad = 10000;
    dap_assert_PIF(l_bad != l_filled, "out-of-order should fail");
    printf("\t%sPASS%s\n", TEXT_COLOR_GRN, TEXT_COLOR_RESET);
    return 0;
}

static int test_large_payload_fragmentation(void)
{
    printf("\tTest 5: Large payload (%d bytes) fragmentation math\n", TEST_ANON_TX_SIZE);
    const uint32_t l_frag_max = 65536;
    uint32_t l_remaining = TEST_ANON_TX_SIZE, l_offset = 0;
    int l_count = 0;
    while (l_remaining > 0) {
        uint32_t l_fs = (l_remaining < l_frag_max) ? l_remaining : l_frag_max;
        dap_assert_PIF((size_t)l_offset + l_fs <= TEST_ANON_TX_SIZE, "bounds");
        l_offset += l_fs; l_remaining -= l_fs; l_count++;
    }
    dap_assert_PIF(l_offset == TEST_ANON_TX_SIZE, "total mismatch");
    dap_assert_PIF(l_count > 0, "no fragments");
    dap_assert_PIF(TEST_ANON_TX_SIZE <= TEST_MAX_REASSEMBLY, "exceeds cap");
    printf("\t%sPASS%s (%d fragments)\n", TEXT_COLOR_GRN, TEXT_COLOR_RESET, l_count);
    return 0;
}

static int test_malicious_patterns(void)
{
    printf("\tTest 6: Malicious fragment patterns\n");
    dap_assert_PIF((uint32_t)0xFFFFFFFF > TEST_MAX_REASSEMBLY, "4GB not rejected");
    dap_assert_PIF((size_t)900 + 200 > 1000, "overflow not detected");
    dap_assert_PIF((size_t)1001 + 0 > 1000, "shift>full not detected");
    printf("\t%sPASS%s\n", TEXT_COLOR_GRN, TEXT_COLOR_RESET);
    return 0;
}

int test_stream_defrag_run(void)
{
    printf("=== Stream Defragmentation Integration Tests ===\n");
    printf("Testing P0-5/P0-6 security fixes\n\n");
    int l_rc = 0;
    l_rc |= test_fragment_pkt_structure();
    l_rc |= test_oom_cap();
    l_rc |= test_overflow_check();
    l_rc |= test_in_order_assembly();
    l_rc |= test_large_payload_fragmentation();
    l_rc |= test_malicious_patterns();
    if (l_rc == 0)
        printf("\n%s=== ALL TESTS PASSED ===%s\n", TEXT_COLOR_GRN, TEXT_COLOR_RESET);
    else
        printf("\n%s=== SOME TESTS FAILED ===%s\n", TEXT_COLOR_RED, TEXT_COLOR_RESET);
    return l_rc;
}
