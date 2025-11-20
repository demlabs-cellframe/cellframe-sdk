/*
 * Minimal unit tests for Ledger Light Cache structures and packing.
 * Focus: dap_ledger_cache_gdb_record_t header fields and meta+ref layout.
 */

#include "dap_common.h"
#include "dap_test.h"
#include "dap_strfuncs.h"
#include "dap_hash.h"
#include "dap_chain_ledger_pvt.h"

// Local copy of light-cache record header for layout verification
#define TEST_DAP_LEDGER_CACHE_GDB_FORMAT_ID   0x4C444743u /* 'LDGC' */
#define TEST_DAP_LEDGER_GDB_VERSION 2
typedef struct test_dap_ledger_cache_gdb_record {
    uint32_t format_id;
    uint16_t version;
    uint16_t flags;
    uint64_t cache_size;
    uint64_t ref_size;
    uint8_t  data[];
} DAP_ALIGN_PACKED test_dap_ledger_cache_gdb_record_t;

void test_ledger_light_cache_structs(void)
{
    dap_print_module_name("Ledger Light Cache: Record Header/Layout");

    // Prepare a fake cache_data + out_metadata (2 outs)
    struct {
        struct {
            dap_time_t ts_created;
            uint32_t n_outs;
            uint32_t n_outs_used;
            char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
            byte_t flags;
            dap_time_t ts_spent;
            dap_chain_srv_uid_t tag;
            dap_chain_tx_tag_action_type_t action;
        } DAP_ALIGN_PACKED cache_data;
        dap_ledger_tx_out_metadata_t out_meta[2];
    } __attribute__((packed)) meta_block = {0};

    meta_block.cache_data.ts_created = 1700000000;
    meta_block.cache_data.n_outs = 2;
    meta_block.cache_data.n_outs_used = 1;
    dap_strncpy(meta_block.cache_data.token_ticker, "AAA", DAP_CHAIN_TICKER_SIZE_MAX);
    meta_block.cache_data.action = DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REGULAR;
    // Fill out_metadata with known hashes
    dap_hash_fast_t h0 = {0}, h1 = {0};
    h0.raw[0] = 0xAA; h1.raw[0] = 0xBB;
    meta_block.out_meta[0].tx_spent_hash_fast = h0;
    meta_block.out_meta[0].trackers = NULL;
    meta_block.out_meta[1].tx_spent_hash_fast = h1;
    meta_block.out_meta[1].trackers = NULL;

    // Prepare ref
    dap_ledger_tx_ref_t ref = {0};
    ref.chain_id.uint64 = 0x1234;
    ref.cell_id.uint64 = 0x55;
    ref.file_offset = 0x10203040;
    ref.datum_offset_in_block = 0x44;
    ref.tx_size = 777;
    ref.atom_hash = (dap_hash_fast_t){ .raw = {1,2,3,4} };

    const size_t cache_size = sizeof(meta_block);
    const size_t ref_size = sizeof(ref);
    const size_t rec_size = sizeof(test_dap_ledger_cache_gdb_record_t) + cache_size + ref_size;

    // Allocate and pack record
    test_dap_ledger_cache_gdb_record_t *rec = (test_dap_ledger_cache_gdb_record_t *)DAP_NEW_Z_SIZE(test_dap_ledger_cache_gdb_record_t, rec_size);
    dap_test(rec != NULL, "Allocated record buffer");
    rec->format_id = TEST_DAP_LEDGER_CACHE_GDB_FORMAT_ID;
    rec->version = TEST_DAP_LEDGER_GDB_VERSION;
    rec->flags = 0;
    rec->cache_size = cache_size;
    rec->ref_size = ref_size;
    memcpy(rec->data, &meta_block, cache_size);
    memcpy(rec->data + cache_size, &ref, ref_size);

    // Check header fields
    dap_assert(rec->format_id == TEST_DAP_LEDGER_CACHE_GDB_FORMAT_ID, "Format ID matches");
    dap_assert(rec->version == TEST_DAP_LEDGER_GDB_VERSION, "Version matches");
    dap_assert(rec->cache_size == cache_size, "Cache size matches");
    dap_assert(rec->ref_size == ref_size, "Ref size matches");

    // Unpack to a fresh tx_item
    dap_ledger_tx_item_t *item = DAP_NEW_Z_SIZE(dap_ledger_tx_item_t, sizeof(dap_ledger_tx_item_t) - sizeof(item->cache_data) + cache_size);
    dap_test(item != NULL, "Allocated tx item");
    memcpy(&item->cache_data, rec->data, cache_size);
    memcpy(&item->ref, rec->data + cache_size, sizeof(dap_ledger_tx_ref_t));

    // Validate round-trip
    dap_assert(item->cache_data.n_outs == 2, "n_outs=2");
    dap_assert(!dap_strcmp(item->cache_data.token_ticker, "AAA"), "Ticker preserved");
    dap_assert(item->cache_data.action == DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REGULAR, "Action preserved");
    dap_assert(item->ref.chain_id.uint64 == 0x1234, "Ref chain_id ok");
    dap_assert(item->ref.cell_id.uint64 == 0x55, "Ref cell_id ok");
    dap_assert(item->ref.file_offset == (off_t)0x10203040, "Ref file_offset ok");
    dap_assert(item->ref.datum_offset_in_block == 0x44, "Ref datum_offset ok");
    dap_assert(item->ref.tx_size == 777, "Ref tx_size ok");
    dap_assert(item->out_metadata[0].tx_spent_hash_fast.raw[0] == 0xAA, "Out0 hash ok");
    dap_assert(item->out_metadata[1].tx_spent_hash_fast.raw[0] == 0xBB, "Out1 hash ok");

    DAP_DELETE(item);
    DAP_DELETE(rec);
}

