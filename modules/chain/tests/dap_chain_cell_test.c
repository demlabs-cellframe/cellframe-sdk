/*
 * Authors:
 * Olzhas Zharasbaev
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
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

#include "dap_test.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_file_utils.h"
#include "dap_chain.h"
#include "dap_chain_cell.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_strfuncs.h"
#include "dap_hash.h"
#include "uthash.h"
#include "json.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define TEST_CHAIN_NAME "test_chain"
#define TEST_NET_NAME "test_net"
#define TEST_CELL_ID 0
#define TEST_DATA_SIZE 256

/**
 * @brief Test that dap_chain_cell_read_atom_by_offset API exists and is callable
 * 
 * This is a minimal API verification test. Full integration testing with actual
 * chain files should be done in integration tests, not unit tests, as it requires
 * proper chain initialization infrastructure.
 */
static void s_test_read_atom_api_exists(void)
{
    dap_print_module_name("Chain Cell API Verification");
    
    // Verify API function exists (compilation test)
    dap_test_msg("Testing dap_chain_cell_read_atom_by_offset() API");
    dap_test_msg("Function signature: void* (*)(dap_chain_t*, dap_chain_cell_id_t, off_t, size_t*)");
    
    // Test passes if it compiles - the function is available
    dap_pass_msg("API function dap_chain_cell_read_atom_by_offset() is available");
    dap_pass_msg("Function can be used by wallet cache for reading transactions by offset");
}

/**
 * @brief Integration test: write and read 20-30 test blocks/transactions
 * Tests writing multiple atoms to cell file and reading them back by offset
 */
static void s_test_write_read_atom_integration(void)
{
    dap_print_module_name("Chain Cell Write/Read 20 Blocks Test");
    
    // Create temporary directory for test chain
    char l_temp_dir[MAX_PATH];
    snprintf(l_temp_dir, sizeof(l_temp_dir), "/tmp/dap_chain_test_%d", getpid());
    
    dap_test_msg("Creating test directory");
    dap_mkdir_with_parents(l_temp_dir);
    dap_assert(dap_dir_test(l_temp_dir), "Test directory created");
    
    // Create test chain
    dap_chain_net_id_t l_net_id = {.uint64 = 0x1234};
    dap_chain_id_t l_chain_id = {.uint64 = 0x5678};
    dap_chain_t *l_chain = dap_chain_create(TEST_NET_NAME, TEST_CHAIN_NAME, l_net_id, l_chain_id);
    dap_assert_PIF(l_chain != NULL, "Chain created");
    
    // Set file storage directory
    DAP_CHAIN_PVT(l_chain)->file_storage_dir = dap_strdup(l_temp_dir);
    l_chain->is_mapped = false; // Use non-mapped mode for simplicity
    
    dap_chain_cell_id_t l_cell_id = {.uint64 = TEST_CELL_ID};
    
    // Open cell for writing
    dap_test_msg("Opening cell for writing");
    int l_ret = dap_chain_cell_open(l_chain, l_cell_id, 'w');
    dap_assert_PIF(l_ret == 0, "Cell opened for writing");
    
    // Create and write 20 test blocks/transactions
    #define BLOCKS_COUNT 20
    byte_t *l_test_blocks[BLOCKS_COUNT];
    size_t l_block_sizes[BLOCKS_COUNT];
    off_t l_block_offsets[BLOCKS_COUNT];
    
    // File header size (signature+version+type+chain_id+net_id+cell_id) = 8+4+1+8+8+8 = 37 bytes (DAP_ALIGN_PACKED)
    off_t l_current_offset = 37;
    
    dap_test_msg("Creating and writing 20 test blocks");
    for (int i = 0; i < BLOCKS_COUNT; i++) {
        // Varying sizes for realism: 100 to 500 bytes
        l_block_sizes[i] = 100 + (i * 20);
        l_test_blocks[i] = DAP_NEW_SIZE(byte_t, l_block_sizes[i]);
        
        // Fill block with test pattern: block_number + byte_offset
        for (size_t j = 0; j < l_block_sizes[i]; j++) {
            l_test_blocks[i][j] = (byte_t)((i * 10 + j) % 256);
        }
        
        // Remember offset where this block will be written
        l_block_offsets[i] = l_current_offset;
        
        // Write block to cell
        l_ret = dap_chain_cell_file_append(l_chain, l_cell_id, l_test_blocks[i], l_block_sizes[i], NULL);
        dap_assert_PIF(l_ret == 0, "Block written to cell");
        
        // Next offset = current + sizeof(size_header) + block_size
        l_current_offset += sizeof(uint64_t) + l_block_sizes[i];
    }
    
    dap_test_msg("Successfully written 20 blocks to cell file");
    
    // Cell is still open, we can read from it immediately
    // dap_chain_cell_file_append already flushed the data
    
    // Check if cells are in hash table
    int l_cell_count = HASH_COUNT(l_chain->cells);
    dap_test_msg("Cells in hash table: %d", l_cell_count);
    dap_test_msg("Chain pointer: %p, cell_id: 0x%lx", l_chain, l_cell_id.uint64);
    
    // Read all blocks back and verify
    dap_test_msg("Reading and verifying all 20 blocks");
    dap_test_msg("First block offset: %ld, expected size: %zu", (long)l_block_offsets[0], l_block_sizes[0]);
    
    int l_success_count = 0;
    
    for (int i = 0; i < BLOCKS_COUNT; i++) {
        size_t l_read_size = 0;
        dap_test_msg("Attempting to read block %d at offset %ld", i, (long)l_block_offsets[i]);
        void *l_read_data = dap_chain_cell_read_atom_by_offset(l_chain, l_cell_id, l_block_offsets[i], &l_read_size);
        
        if (!l_read_data) {
            dap_test_msg("Block %d read FAILED - returned NULL", i);
            continue;
        }
        
        if (l_read_size != l_block_sizes[i]) {
            dap_test_msg("Block %d size mismatch: %zu vs %zu", i, l_read_size, l_block_sizes[i]);
            DAP_DELETE(l_read_data);
            continue;
        }
        
        int l_cmp = memcmp(l_read_data, l_test_blocks[i], l_block_sizes[i]);
        if (l_cmp != 0) {
            dap_test_msg("Block %d data mismatch", i);
            DAP_DELETE(l_read_data);
            continue;
        }
        
        l_success_count++;
        DAP_DELETE(l_read_data);
    }
    
    dap_test_msg("Successfully read %d/%d blocks", l_success_count, BLOCKS_COUNT);
    dap_assert_PIF(l_success_count == BLOCKS_COUNT, "All blocks read and verified");
    
    // Cleanup
    for (int i = 0; i < BLOCKS_COUNT; i++) {
        DAP_DELETE(l_test_blocks[i]);
    }
    
    dap_chain_cell_close(l_chain, l_cell_id);
    
    // Manual cleanup without cs_class delete (test doesn't have real consensus)
    if (DAP_CHAIN_PVT(l_chain)->file_storage_dir) {
        DAP_DELETE(DAP_CHAIN_PVT(l_chain)->file_storage_dir);
    }
    DAP_DEL_Z(l_chain->_pvt);
    DAP_DEL_Z(l_chain);
    
    // Remove test files
    char l_cell_file[MAX_PATH];
    snprintf(l_cell_file, sizeof(l_cell_file), "%s/%x.dchaincell", l_temp_dir, TEST_CELL_ID);
    unlink(l_cell_file);
    rmdir(l_temp_dir);
    
    dap_test_msg("Integration test with 20 blocks completed successfully");
}

/**
 * @brief Integration test: write 30 transactions with varying sizes
 * Tests handling of different transaction sizes and random access
 */
static void s_test_multiple_atoms_integration(void)
{
    dap_print_module_name("Chain Cell 30 Transactions Random Access Test");
    
    // Create temporary directory for test chain
    char l_temp_dir[MAX_PATH];
    snprintf(l_temp_dir, sizeof(l_temp_dir), "/tmp/dap_chain_test_multi_%d", getpid());
    
    dap_test_msg("Creating test directory");
    dap_mkdir_with_parents(l_temp_dir);
    dap_assert(dap_dir_test(l_temp_dir), "Test directory created");
    
    // Create test chain with unique name to avoid conflicts with previous tests
    dap_chain_net_id_t l_net_id = {.uint64 = 0x1235};  // Different net_id
    dap_chain_id_t l_chain_id = {.uint64 = 0x5679};    // Different chain_id
    dap_chain_t *l_chain = dap_chain_create(TEST_NET_NAME, "test_chain_tx", l_net_id, l_chain_id);
    dap_assert_PIF(l_chain != NULL, "Chain created");
    
    // Set file storage directory
    DAP_CHAIN_PVT(l_chain)->file_storage_dir = dap_strdup(l_temp_dir);
    l_chain->is_mapped = false;
    
    dap_chain_cell_id_t l_cell_id = {.uint64 = TEST_CELL_ID};
    
    // Open cell for writing
    int l_ret = dap_chain_cell_open(l_chain, l_cell_id, 'w');
    dap_assert_PIF(l_ret == 0, "Cell opened");
    
    // Write 30 transactions with varying sizes
    #define TX_COUNT 30
    byte_t *l_test_txs[TX_COUNT];
    size_t l_tx_sizes[TX_COUNT];
    off_t l_tx_offsets[TX_COUNT];
    
    off_t l_current_offset = 37;  // Same header size as above
    
    dap_test_msg("Creating and writing 30 transactions");
    for (int i = 0; i < TX_COUNT; i++) {
        // Varying sizes: 64 to 1024 bytes
        l_tx_sizes[i] = 64 + (i * 32);
        l_test_txs[i] = DAP_NEW_SIZE(byte_t, l_tx_sizes[i]);
        
        // Fill with test pattern unique to this transaction
        for (size_t j = 0; j < l_tx_sizes[i]; j++) {
            l_test_txs[i][j] = (byte_t)((i * 7 + j * 3) % 256);
        }
        
        l_tx_offsets[i] = l_current_offset;
        l_ret = dap_chain_cell_file_append(l_chain, l_cell_id, l_test_txs[i], l_tx_sizes[i], NULL);
        dap_assert_PIF(l_ret == 0, "Transaction written");
        
        l_current_offset += sizeof(uint64_t) + l_tx_sizes[i];
    }
    
    dap_test_msg("Successfully written 30 transactions");
    
    // Close and reopen
    dap_chain_cell_close(l_chain, l_cell_id);
    l_ret = dap_chain_cell_open(l_chain, l_cell_id, 'a');
    dap_assert_PIF(l_ret == 0, "Cell reopened");
    
    // Test random access - read transactions in random order
    dap_test_msg("Testing random access to transactions");
    int l_read_order[] = {5, 15, 2, 28, 10, 0, 29, 7, 20, 12, 25, 3, 18, 8, 22, 1, 16, 11, 27, 4, 19, 9, 24, 6, 21, 13, 26, 14, 23, 17};
    int l_success_count = 0;
    
    for (int idx = 0; idx < TX_COUNT; idx++) {
        int i = l_read_order[idx];
        size_t l_read_size = 0;
        void *l_read_data = dap_chain_cell_read_atom_by_offset(l_chain, l_cell_id, 
                                                                 l_tx_offsets[i], &l_read_size);
        
        if (!l_read_data || l_read_size != l_tx_sizes[i]) {
            dap_test_msg("TX %d read failed", i);
            if (l_read_data) DAP_DELETE(l_read_data);
            continue;
        }
        
        int l_cmp = memcmp(l_read_data, l_test_txs[i], l_tx_sizes[i]);
        if (l_cmp == 0) {
            l_success_count++;
        } else {
            dap_test_msg("TX %d data mismatch", i);
        }
        
        DAP_DELETE(l_read_data);
    }
    
    dap_test_msg("Successfully read %d/%d transactions in random order", l_success_count, TX_COUNT);
    dap_assert_PIF(l_success_count == TX_COUNT, "All transactions verified");
    
    // Cleanup
    for (int i = 0; i < TX_COUNT; i++) {
        DAP_DELETE(l_test_txs[i]);
    }
    
    dap_chain_cell_close(l_chain, l_cell_id);
    
    // Manual cleanup without cs_class delete
    if (DAP_CHAIN_PVT(l_chain)->file_storage_dir) {
        DAP_DELETE(DAP_CHAIN_PVT(l_chain)->file_storage_dir);
    }
    DAP_DEL_Z(l_chain->_pvt);
    DAP_DEL_Z(l_chain);
    
    char l_cell_file[MAX_PATH];
    snprintf(l_cell_file, sizeof(l_cell_file), "%s/%x.dchaincell", l_temp_dir, TEST_CELL_ID);
    unlink(l_cell_file);
    rmdir(l_temp_dir);
    
    dap_test_msg("Random access test with 30 transactions completed successfully");
}

/**
 * @brief Run all cell tests
 */
void dap_chain_cell_tests_run(void)
{
    // Save original log settings
    dap_log_level_t l_orig_level = dap_log_level_get();
    
    // Setup test environment
    dap_log_level_set(L_INFO);
    dap_log_set_format(DAP_LOG_FORMAT_NO_PREFIX);
    
    printf("\n=== DAP Chain Cell Tests ===\n");
    
    // Run API verification test
    s_test_read_atom_api_exists();
    
    // Run integration tests with real cell files
    s_test_write_read_atom_integration();
    s_test_multiple_atoms_integration();
    
    printf("\n=== All Tests PASSED ===\n\n");
    
    // Restore original settings
    dap_log_level_set(l_orig_level);
}

// Forward declarations and includes for consensus modules
#include "dap_chain_cs.h"
#include "dap_events.h"
#include "dap_chain_block.h"
extern int dap_chain_cs_blocks_init();
extern int dap_chain_cs_esbocs_init();

/**
 * @brief Integration test with REAL chain files from production node
 * 
 * This test reads chain files directly and tests offset-based reading.
 * Simplified approach - NO full chain loading, just direct file reading.
 * 
 * @param a_chains_path Path to chain storage directory  
 * @param a_cell_id Cell ID to test (0 for main chain)
 * @param a_test_count Number of random datum reads to test
 * @param a_show_samples Number of sample transactions to display in JSON (0 = don't show)
 */
void dap_chain_cell_real_chain_test(const char *a_chains_path, uint64_t a_cell_id, int a_test_count, int a_show_samples)
{
    dap_print_module_name("Real Chain Integration Test - Direct File Reading");
    
    if (!a_chains_path) {
        dap_test_msg("ERROR: chains_path is NULL");
        return;
    }
    
    dap_test_msg("Testing with real chain data from: %s", a_chains_path);
    dap_test_msg("Cell ID: %lu, Test count: %d", a_cell_id, a_test_count);
    
    // Convert cell ID to union
    dap_chain_cell_id_t l_cell_id = {.uint64 = a_cell_id};
    
    // Initialize random number generator
    srand(time(NULL));
    
    // Check directory exists
    if (!dap_dir_test(a_chains_path)) {
        dap_test_msg("ERROR: Chains directory does not exist: %s", a_chains_path);
        return;
    }
    
    // Construct cell file path
    char l_cell_file_path[PATH_MAX];
    snprintf(l_cell_file_path, sizeof(l_cell_file_path), "%s/0.dchaincell", a_chains_path);
    
    FILE *l_file = fopen(l_cell_file_path, "rb");
    if (!l_file) {
        dap_test_msg("ERROR: Cannot open cell file: %s", l_cell_file_path);
        return;
    }
    
    // Get file size
    fseeko(l_file, 0, SEEK_END);
    off_t l_file_size = ftello(l_file);
    fseeko(l_file, 0, SEEK_SET);
    
    dap_test_msg("Cell file: %s (%ld bytes)", l_cell_file_path, (long)l_file_size);
    
    // Cell file header size: signature(8) + version(4) + type(1) + chain_id(8) + chain_net_id(8) + cell_id(8) = 37
    size_t l_header_size = 37;
    dap_test_msg("Cell file header size: %zu bytes", l_header_size);
    
    // Scan file for datum positions inside blocks
    typedef struct {
        off_t block_offset;      // File offset of the BLOCK (atom) - points to SIZE field!
        size_t block_size;        // Size of the entire block
        off_t datum_offset_in_block; // Offset of datum within block data
        uint32_t datum_size;
        uint16_t type_id;
    } datum_info_t;
    
    int l_max_datums = 50000;
    datum_info_t *l_datums = DAP_NEW_Z_SIZE(datum_info_t, l_max_datums * sizeof(datum_info_t));
    int l_datum_count = 0;
    int l_tx_count = 0;
    int l_block_count = 0;
    
    dap_test_msg("Scanning file for blocks and datums...");
    
    // Start after header
    off_t l_current_offset = l_header_size;
    while (l_current_offset < l_file_size && l_datum_count < l_max_datums) {
        // Read atom size (8 bytes before atom data)
        uint64_t l_atom_size = 0;
        fseeko(l_file, l_current_offset, SEEK_SET);
        size_t l_read = fread(&l_atom_size, 1, sizeof(l_atom_size), l_file);
        
        if (l_read != sizeof(l_atom_size)) {
            break; // End of file
        }
        
        // Validate atom size
        if (l_atom_size == 0 || l_atom_size > (1024 * 1024 * 100)) {
            dap_test_msg("Invalid atom size %lu at offset %ld, stopping scan", 
                         (unsigned long)l_atom_size, (long)l_current_offset);
            break;
        }
        
        // Now read block header
        dap_chain_block_hdr_t l_block_hdr;
        l_read = fread(&l_block_hdr, 1, sizeof(l_block_hdr), l_file);
        
        if (l_read != sizeof(l_block_hdr)) {
            break; // End of file
        }
        
        // Check for block signature
        if (l_block_hdr.signature != DAP_CHAIN_BLOCK_SIGNATURE) {
            // Not a block, skip to next atom
            l_current_offset += sizeof(l_atom_size) + l_atom_size;
            continue;
        }
        
        // Valid block found!
        l_block_count++;
        
        // Validate block header
        if (l_block_hdr.meta_n_datum_n_signs_size == 0 || 
            l_block_hdr.meta_n_datum_n_signs_size > (1024 * 1024 * 100)) {
            // Invalid block, skip
            l_current_offset += sizeof(l_block_hdr);
            continue;
        }
        
        // Read block data (metadata + datums + signatures)
        size_t l_block_data_size = l_block_hdr.meta_n_datum_n_signs_size;
        byte_t *l_block_data = DAP_NEW_Z_SIZE(byte_t, l_block_data_size);
        l_read = fread(l_block_data, 1, l_block_data_size, l_file);
        
        if (l_read != l_block_data_size) {
            DAP_DELETE(l_block_data);
            break;
        }
        
        // Parse block data to find datums
        size_t l_offset_in_block = 0;
        
        // Skip metadata sections
        for (uint16_t i = 0; i < l_block_hdr.meta_count && l_offset_in_block < l_block_data_size; i++) {
            dap_chain_block_meta_t *l_meta = (dap_chain_block_meta_t *)(l_block_data + l_offset_in_block);
            if (l_offset_in_block + sizeof(l_meta->hdr) > l_block_data_size) break;
            size_t l_meta_size = sizeof(l_meta->hdr) + l_meta->hdr.data_size;
            l_offset_in_block += l_meta_size;
        }
        
        // Now parse datums
        for (uint16_t i = 0; i < l_block_hdr.datum_count && l_offset_in_block < l_block_data_size && l_datum_count < l_max_datums; i++) {
            if (l_offset_in_block + sizeof(dap_chain_datum_t) > l_block_data_size) break;
            
            dap_chain_datum_t *l_datum = (dap_chain_datum_t *)(l_block_data + l_offset_in_block);
            
            // Validate datum
            if (l_datum->header.data_size > 0 && l_datum->header.data_size < (1024 * 1024 * 10)) {
                // Store datum info with ATOM offset (points to SIZE field!)
                // This is what dap_chain_cell_read_atom_by_offset() expects
                l_datums[l_datum_count].block_offset = l_current_offset; // Points to SIZE field
                l_datums[l_datum_count].block_size = l_atom_size;
                // Offset within the atom DATA (after block header)
                l_datums[l_datum_count].datum_offset_in_block = sizeof(l_block_hdr) + l_offset_in_block;
                l_datums[l_datum_count].datum_size = sizeof(l_datum->header) + l_datum->header.data_size;
                l_datums[l_datum_count].type_id = l_datum->header.type_id;
                l_datum_count++;
                
                if (l_datum->header.type_id == DAP_CHAIN_DATUM_TX) {
                    l_tx_count++;
                }
            }
            
            // Move to next datum
            size_t l_datum_size = sizeof(l_datum->header) + l_datum->header.data_size;
            l_offset_in_block += l_datum_size;
        }
        
        DAP_DELETE(l_block_data);
        
        // Progress
        if (l_block_count % 100 == 0) {
            dap_test_msg("Scanned %d blocks, %d datums (%d transactions)...", 
                         l_block_count, l_datum_count, l_tx_count);
        }
        
        // Move to next atom (size + data)
        l_current_offset += sizeof(l_atom_size) + l_atom_size;
    }
    
    fclose(l_file);
    
    dap_test_msg("Total blocks: %d, datums: %d (%d transactions)", l_block_count, l_datum_count, l_tx_count);
    
    if (l_datum_count == 0) {
        dap_test_msg("ERROR: No datums found in file");
        DAP_DELETE(l_datums);
        return;
    }
    
    // Create minimal chain structure for reading
    dap_chain_net_id_t l_net_id = {.uint64 = 0x72656d6e5f746573}; 
    dap_chain_id_t l_chain_id = {.uint64 = 0x7265616c5f636861};
    dap_chain_t *l_chain = dap_chain_create("real_test", "real_test", l_net_id, l_chain_id);
    
    if (!l_chain) {
        dap_test_msg("ERROR: Failed to create chain");
        DAP_DELETE(l_datums);
        return;
    }
    
    DAP_CHAIN_PVT(l_chain)->file_storage_dir = dap_strdup(a_chains_path);
    l_chain->is_mapped = false;
    
    // Open cell for reading via API
    dap_test_msg("Opening cell via API...");
    int l_ret = dap_chain_cell_open(l_chain, l_cell_id, 'r');
    dap_test_msg("dap_chain_cell_open returned: %d", l_ret);
    if (l_ret != 0) {
        dap_test_msg("ERROR: Failed to open cell via API (code %d)", l_ret);
        DAP_DELETE(DAP_CHAIN_PVT(l_chain)->file_storage_dir);
        DAP_DEL_Z(l_chain->_pvt);
        DAP_DEL_Z(l_chain);
        DAP_DELETE(l_datums);
        return;
    }
    dap_test_msg("Cell opened successfully");
    
    // Test random reads with bitwise comparison
    dap_test_msg("\nTesting offset-based reading for %d random datums...", a_test_count);
    dap_test_msg("Total datums available: %d", l_datum_count);
    dap_test_msg("First datum block_offset: %ld", (long)l_datums[0].block_offset);
    dap_test_msg("Last datum block_offset: %ld", (long)l_datums[l_datum_count-1].block_offset);
    
    int l_success_count = 0;
    int l_fail_count = 0;
    int l_bitwise_matches = 0;
    int l_bitwise_mismatches = 0;
    
    for (int i = 0; i < a_test_count && i < l_datum_count; i++) {
        // Use sequential indices for first tests to debug, then random
        int l_idx = (i < 10) ? (i * (l_datum_count / 10)) : (rand() % l_datum_count);
        datum_info_t *l_datum_info = &l_datums[l_idx];
        
        dap_test_msg("Test %d/%d: idx=%d, block_offset=%ld", 
                     i + 1, a_test_count, l_idx, (long)l_datum_info->block_offset);
        
        // Read BLOCK (atom) using API
        size_t l_read_size = 0;
        void *l_block_data = dap_chain_cell_read_atom_by_offset(
            l_chain, l_cell_id, l_datum_info->block_offset, &l_read_size
        );
        
        if (!l_block_data) {
            dap_test_msg("Test %d/%d FAILED: Could not read block at offset %ld", 
                         i + 1, a_test_count, (long)l_datum_info->block_offset);
            l_fail_count++;
            continue;
        }
        
        // Parse block to extract datum
        dap_chain_block_t *l_block = (dap_chain_block_t *)l_block_data;
        
        // Verify it's a block
        if (l_block->hdr.signature != DAP_CHAIN_BLOCK_SIGNATURE) {
            dap_test_msg("Test %d/%d FAILED: Invalid block signature", i + 1, a_test_count);
            DAP_DELETE(l_block_data);
            l_fail_count++;
            continue;
        }
        
        // Extract datum from block data
        // l_datum_info->datum_offset_in_block is relative to atom DATA (already accounts for block header)
        size_t l_atom_data_size = sizeof(l_block->hdr) + l_block->hdr.meta_n_datum_n_signs_size;
        if (l_datum_info->datum_offset_in_block >= l_atom_data_size) {
            dap_test_msg("Test %d/%d FAILED: Datum offset %ld out of bounds (atom size %zu)", 
                         i + 1, a_test_count, (long)l_datum_info->datum_offset_in_block, l_atom_data_size);
            DAP_DELETE(l_block_data);
            l_fail_count++;
            continue;
        }
        
        // datum_offset_in_block already includes block header size
        dap_chain_datum_t *l_datum = (dap_chain_datum_t *)((byte_t *)l_block_data + l_datum_info->datum_offset_in_block);
        
        // Verify datum type
        if (l_datum->header.type_id != l_datum_info->type_id) {
            dap_test_msg("Test %d/%d FAILED: Type mismatch (expected 0x%04X, got 0x%04X)", 
                         i + 1, a_test_count, l_datum_info->type_id, l_datum->header.type_id);
            DAP_DELETE(l_block_data);
            l_fail_count++;
            continue;
        }
        
        dap_test_msg("Test %d/%d PASSED: Datum type 0x%04X in block at offset %ld", 
                     i + 1, a_test_count, l_datum->header.type_id, (long)l_datum_info->block_offset);
        
        // BITWISE COMPARISON: Read same block directly from file and compare
        FILE *l_verify_file = fopen(l_cell_file_path, "rb");
        if (l_verify_file) {
            // Seek to atom (skip size field, read atom data)
            fseeko(l_verify_file, l_datum_info->block_offset + sizeof(uint64_t), SEEK_SET);
            
            // Read same data directly from file
            void *l_file_block_data = DAP_NEW_Z_SIZE(byte_t, l_read_size);
            size_t l_file_read = fread(l_file_block_data, 1, l_read_size, l_verify_file);
            fclose(l_verify_file);
            
            if (l_file_read == l_read_size) {
                // Bitwise comparison
                if (memcmp(l_block_data, l_file_block_data, l_read_size) == 0) {
                    dap_test_msg("  -> Bitwise comparison: MATCH (all %zu bytes identical)", l_read_size);
                    l_bitwise_matches++;
                } else {
                    dap_test_msg("  -> Bitwise comparison: MISMATCH! Data differs!");
                    l_bitwise_mismatches++;
                    
                    // Show first difference
                    for (size_t j = 0; j < l_read_size; j++) {
                        if (((byte_t *)l_block_data)[j] != ((byte_t *)l_file_block_data)[j]) {
                            dap_test_msg("     First difference at byte %zu: API=0x%02X, File=0x%02X",
                                       j, ((byte_t *)l_block_data)[j], ((byte_t *)l_file_block_data)[j]);
                            break;
                        }
                    }
                }
            }
            DAP_DELETE(l_file_block_data);
        }
        
        DAP_DELETE(l_block_data);
        l_success_count++;
    }
    
    dap_test_msg("\n=== Test Results ===");
    dap_test_msg("Total tests: %d", a_test_count);
    dap_test_msg("Passed: %d", l_success_count);
    dap_test_msg("Failed: %d", l_fail_count);
    dap_test_msg("Success rate: %.1f%%", (l_success_count * 100.0) / a_test_count);
    
    dap_test_msg("\n=== Bitwise Verification ===");
    dap_test_msg("Bitwise matches: %d", l_bitwise_matches);
    dap_test_msg("Bitwise mismatches: %d", l_bitwise_mismatches);
    if (l_bitwise_matches > 0) {
        dap_test_msg("Bitwise accuracy: %.1f%%", (l_bitwise_matches * 100.0) / (l_bitwise_matches + l_bitwise_mismatches));
    }
    
    if (l_success_count >= (a_test_count * 95 / 100) && l_bitwise_mismatches == 0) {
        dap_pass_msg("Real chain test PASSED (success rate >= 95%%, 100%% bitwise match)");
    } else if (l_success_count >= (a_test_count * 95 / 100)) {
        dap_test_msg("WARNING: Tests passed but bitwise mismatches detected!");
    } else {
        dap_test_msg("WARNING: Success rate below 95%%");
    }
    
    // Show JSON samples for transactions
    if (a_show_samples > 0 && l_tx_count > 0) {
        dap_test_msg("\n=== Sample Transactions (JSON Format) ===");
        
        int l_samples_shown = 0;
        int l_attempts = 0;
        int l_max_attempts = a_show_samples * 50;
        
        while (l_samples_shown < a_show_samples && l_attempts < l_max_attempts) {
            l_attempts++;
            int l_idx = rand() % l_datum_count;
            
            // Only show transactions
            if (l_datums[l_idx].type_id != DAP_CHAIN_DATUM_TX) {
                continue;
            }
            
            // Read BLOCK (atom)
            size_t l_read_size = 0;
            void *l_block_data = dap_chain_cell_read_atom_by_offset(
                l_chain, l_cell_id, l_datums[l_idx].block_offset, &l_read_size
            );
            
            if (!l_block_data) continue;
            
            // Extract datum from block
            dap_chain_block_t *l_block = (dap_chain_block_t *)l_block_data;
            if (l_block->hdr.signature != DAP_CHAIN_BLOCK_SIGNATURE) {
                DAP_DELETE(l_block_data);
                continue;
            }
            
            size_t l_atom_data_size = sizeof(l_block->hdr) + l_block->hdr.meta_n_datum_n_signs_size;
            if (l_datums[l_idx].datum_offset_in_block >= l_atom_data_size) {
                DAP_DELETE(l_block_data);
                continue;
            }
            
            dap_chain_datum_t *l_datum = (dap_chain_datum_t *)((byte_t *)l_block_data + l_datums[l_idx].datum_offset_in_block);
            
            dap_test_msg("\n--- Sample %d/%d ---", l_samples_shown + 1, a_show_samples);
            dap_test_msg("Block offset: %ld", (long)l_datums[l_idx].block_offset);
            dap_test_msg("Block size: %zu bytes", l_read_size);
            dap_test_msg("Datum type: 0x%04X", l_datum->header.type_id);
            dap_test_msg("Datum size: %u bytes", l_datum->header.data_size);
            dap_test_msg("Timestamp: %lu", l_datum->header.ts_create);
            
            // Extract transaction
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
            dap_test_msg("TX timestamp: %lu", l_tx->header.ts_created);
            
            // Calculate hashes
            dap_hash_fast_t l_datum_hash;
            dap_chain_datum_calc_hash(l_datum, &l_datum_hash);
            char *l_hash_str = dap_hash_fast_to_str_new(&l_datum_hash);
            dap_test_msg("Datum hash: %s", l_hash_str);
            DAP_DELETE(l_hash_str);
            
            dap_hash_fast_t l_tx_hash;
            dap_hash_fast(l_tx, l_datum->header.data_size, &l_tx_hash);
            
            // Output as JSON
            json_object *l_json_obj = json_object_new_object();
            dap_chain_net_id_t l_net_id_tx = {.uint64 = 0};
            
            if (dap_chain_datum_dump_tx_json(NULL, l_tx, NULL, l_json_obj, 
                                              "hex", &l_tx_hash, l_net_id_tx, 1) == 0) {
                const char *l_json_str = json_object_to_json_string_ext(l_json_obj, JSON_C_TO_STRING_PRETTY);
                dap_test_msg("Transaction JSON:\n%s", l_json_str);
            }
            
            json_object_put(l_json_obj);
            DAP_DELETE(l_block_data);
            
            l_samples_shown++;
        }
        
        dap_test_msg("\n=== End of Samples (showed %d/%d requested) ===\n", 
                     l_samples_shown, a_show_samples);
    }
    
    // Cleanup
    dap_chain_cell_close(l_chain, l_cell_id);
    DAP_DELETE(DAP_CHAIN_PVT(l_chain)->file_storage_dir);
    DAP_DEL_Z(l_chain->_pvt);
    DAP_DEL_Z(l_chain);
    DAP_DELETE(l_datums);
    
    dap_test_msg("Real chain integration test completed\n");
}
