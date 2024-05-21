#include "dap_chain_cs_blocks.h"
#include "dap_test.h"
#include "dap_config.h"
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_block.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_cs.h"

void dap_chain_blocks_test()
{
    dap_test_msg("Start of cs block testing...");
    dap_assert_PIF(dap_chain_cs_blocks_init() == 0, "Initialization of dap consensus block: ");

    dap_assert_PIF(dap_chain_cs_esbocs_init() == 0, "Initialization of esbocs: ");

    const char *l_chain_net_name = "testnet";
    const char *l_chain_name = "testchain";
    dap_chain_net_id_t l_chain_net_id = {.uint64 = 1}; 
    dap_chain_id_t l_chain_id = {.uint64 = 1};

    dap_chain_t *l_chain =  dap_chain_create(l_chain_net_name, l_chain_name, l_chain_net_id, l_chain_id);
    dap_config_t l_cfg = {};
    dap_assert_PIF(dap_chain_cs_create(l_chain, &l_cfg) == 0, "Chain cs creating: ");

    size_t l_block_size = 0;
    dap_chain_block_t *l_block = NULL;
    dap_hash_fast_t l_forked_block_hash = {};
    dap_hash_fast_t l_block_hash = {};
    dap_list_t *l_first_branch_atoms_list = NULL;
    dap_list_t *l_second_branch_atoms_list = NULL;

    l_block = dap_chain_block_new(NULL, &l_block_size);
    dap_assert_PIF(l_block != NULL, "Creating of genesis block:");
    dap_hash_fast(l_block, l_block_size, &l_block_hash);
    // dap_test_msg("Created genesis block %s", dap_chain_hash_fast_to_str_static(&l_block_hash));
    dap_assert_PIF(l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block, l_block_size, &l_block_hash) == ATOM_ACCEPT, "Adding of genesis block: ");
    dap_hash_fast_t *l_block_hash_copy = DAP_DUP_SIZE(&l_block_hash, sizeof(dap_hash_fast_t));
    l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);
    l_second_branch_atoms_list = dap_list_append(l_second_branch_atoms_list, l_block_hash_copy);

    l_block = dap_chain_block_new(&l_block_hash, &l_block_size);
    dap_assert_PIF(l_block != NULL, "Creating of second block:");
    dap_hash_fast(l_block, l_block_size, &l_block_hash);
    // dap_test_msg("Created second block %s", dap_chain_hash_fast_to_str_static(&l_block_hash));
    dap_assert_PIF(l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block, l_block_size, &l_block_hash) == ATOM_ACCEPT, "Adding of second block: ");
    l_block_hash_copy = DAP_DUP_SIZE(&l_block_hash, sizeof(dap_hash_fast_t));
    l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);
    l_second_branch_atoms_list = dap_list_append(l_second_branch_atoms_list, l_block_hash_copy);
    l_forked_block_hash = l_block_hash;

    for (int i = 0; i < 2; i++){
        l_block = dap_chain_block_new(&l_block_hash, &l_block_size);
        // dap_assert_PIF(l_block != NULL, "Creating of block:");
        dap_hash_fast(l_block, l_block_size, &l_block_hash);
        // dap_test_msg("Created block %s", dap_chain_hash_fast_to_str_static(&l_block_hash));
        dap_assert_PIF(l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block, l_block_size, &l_block_hash) == ATOM_ACCEPT, "Adding of block: ");
        dap_hash_fast_t *l_block_hash_copy = DAP_DUP_SIZE(&l_block_hash, sizeof(dap_hash_fast_t));
        l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);
    }
    

    dap_test_msg("Add forked block from %s", dap_chain_hash_fast_to_str_static(&l_forked_block_hash)); 
    l_block_size = 0;
    l_block = dap_chain_block_new(&l_forked_block_hash, &l_block_size);
    // dap_assert_PIF(l_block != NULL, "Creating of forked block:");
    dap_hash_fast(l_block, l_block_size, &l_block_hash);
    // dap_test_msg("Created block %s", dap_chain_hash_fast_to_str_static(&l_block_hash));
    dap_assert_PIF(l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block, l_block_size, &l_block_hash) == ATOM_ACCEPT, "Adding of forked block: ");
    l_block_hash_copy = DAP_DUP_SIZE(&l_block_hash, sizeof(dap_hash_fast_t));
    l_second_branch_atoms_list = dap_list_append(l_second_branch_atoms_list, l_block_hash_copy);

    dap_chain_cell_id_t l_cell_id = {.uint64 = 1};
    size_t l_atom_size_from_iter = 0;
    dap_chain_atom_iter_t *l_iter = l_chain->callback_atom_iter_create(l_chain, l_cell_id, NULL);
    dap_list_t *l_branch_temp = NULL;
    dap_chain_atom_ptr_t l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_FIRST, &l_atom_size_from_iter);
    for (dap_list_t *l_branch_temp = l_first_branch_atoms_list; l_branch_temp && l_atom; 
        l_branch_temp = l_branch_temp->next, l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size_from_iter)){
        dap_test_msg("Check block %s and %s", dap_chain_hash_fast_to_str_static(l_iter->cur_hash), 
                                            dap_chain_hash_fast_to_str_static((dap_hash_fast_t*)l_branch_temp->data));
        dap_assert_PIF(dap_hash_fast_compare(l_iter->cur_hash, (dap_hash_fast_t*)l_branch_temp->data), "Check adding block into forked branch: ");
    }


    dap_test_msg("Add block to forked branch"); 
    l_block_size = 0;
    l_block = dap_chain_block_new(&l_block_hash, &l_block_size);
    // dap_assert_PIF(l_block != NULL, "Creating of forked block:");
    dap_hash_fast(l_block, l_block_size, &l_block_hash);
    // dap_test_msg("Created block %s", dap_chain_hash_fast_to_str_static(&l_block_hash));
    dap_assert_PIF(l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block, l_block_size, &l_block_hash) == ATOM_ACCEPT, "Adding of forked block: ");
    l_block_hash_copy = DAP_DUP_SIZE(&l_block_hash, sizeof(dap_hash_fast_t));
    l_second_branch_atoms_list = dap_list_append(l_second_branch_atoms_list, l_block_hash_copy);

    l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_FIRST, &l_atom_size_from_iter);
    for (dap_list_t *l_branch_temp = l_first_branch_atoms_list; l_branch_temp && l_atom; 
        l_branch_temp = l_branch_temp->next, l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size_from_iter)){
        dap_test_msg("Check block %s and %s", dap_chain_hash_fast_to_str_static(l_iter->cur_hash), 
                                            dap_chain_hash_fast_to_str_static((dap_hash_fast_t*)l_branch_temp->data));
        dap_assert_PIF(dap_hash_fast_compare(l_iter->cur_hash, (dap_hash_fast_t*)l_branch_temp->data), "Check adding block into forked branch: ");
    }

    dap_test_msg("Add block to forked branch");
    l_block_size = 0;
    l_block = dap_chain_block_new(&l_block_hash, &l_block_size);
    // dap_assert_PIF(l_block != NULL, "Creating of forked block:");
    dap_hash_fast(l_block, l_block_size, &l_block_hash);
    // dap_test_msg("Created block %s", dap_chain_hash_fast_to_str_static(&l_block_hash));
    dap_assert_PIF(l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block, l_block_size, &l_block_hash) == ATOM_ACCEPT, "Adding of forked block: ");
    l_block_hash_copy = DAP_DUP_SIZE(&l_block_hash, sizeof(dap_hash_fast_t));
    l_second_branch_atoms_list = dap_list_append(l_second_branch_atoms_list, l_block_hash_copy);

    l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_FIRST, &l_atom_size_from_iter);
    for (dap_list_t *l_branch_temp = l_second_branch_atoms_list; l_branch_temp && l_atom; 
        l_branch_temp = l_branch_temp->next, l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size_from_iter)){
        dap_test_msg("Check block %s and %s", dap_chain_hash_fast_to_str_static(l_iter->cur_hash), 
                                            dap_chain_hash_fast_to_str_static((dap_hash_fast_t*)l_branch_temp->data));
        dap_assert_PIF(dap_hash_fast_compare(l_iter->cur_hash, (dap_hash_fast_t*)l_branch_temp->data), "Check adding block into forked branch: ");
    }

    dap_test_msg("Add block to former main branch");
    l_block_size = 0;
    l_block = dap_chain_block_new((dap_hash_fast_t*)dap_list_last(l_first_branch_atoms_list)->data, &l_block_size);
    // dap_assert_PIF(l_block != NULL, "Creating of forked block:");
    dap_hash_fast(l_block, l_block_size, &l_block_hash);
    // dap_test_msg("Created block %s", dap_chain_hash_fast_to_str_static(&l_block_hash));
    dap_assert_PIF(l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block, l_block_size, &l_block_hash) == ATOM_ACCEPT, "Adding of forked block: ");
    l_block_hash_copy = DAP_DUP_SIZE(&l_block_hash, sizeof(dap_hash_fast_t));
    l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);

    l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_FIRST, &l_atom_size_from_iter);
    for (dap_list_t *l_branch_temp = l_second_branch_atoms_list; l_branch_temp && l_atom; 
        l_branch_temp = l_branch_temp->next, l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size_from_iter)){
        dap_test_msg("Check block %s and %s", dap_chain_hash_fast_to_str_static(l_iter->cur_hash), 
                                            dap_chain_hash_fast_to_str_static((dap_hash_fast_t*)l_branch_temp->data));
        dap_assert_PIF(dap_hash_fast_compare(l_iter->cur_hash, (dap_hash_fast_t*)l_branch_temp->data), "Check adding block into forked branch: ");
    }

    dap_test_msg("Add block to former main branch");
    l_block_size = 0;
    l_block = dap_chain_block_new((dap_hash_fast_t*)dap_list_last(l_first_branch_atoms_list)->data, &l_block_size);
    // dap_assert_PIF(l_block != NULL, "Creating of forked block:");
    dap_hash_fast(l_block, l_block_size, &l_block_hash);
    // dap_test_msg("Created block %s", dap_chain_hash_fast_to_str_static(&l_block_hash));
    dap_assert_PIF(l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block, l_block_size, &l_block_hash) == ATOM_ACCEPT, "Adding of forked block: ");
    l_block_hash_copy = DAP_DUP_SIZE(&l_block_hash, sizeof(dap_hash_fast_t));
    l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);

    l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_FIRST, &l_atom_size_from_iter);
    for (dap_list_t *l_branch_temp = l_first_branch_atoms_list; l_branch_temp && l_atom; 
        l_branch_temp = l_branch_temp->next, l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size_from_iter)){
        dap_test_msg("Check block %s and %s", dap_chain_hash_fast_to_str_static(l_iter->cur_hash), 
                                            dap_chain_hash_fast_to_str_static((dap_hash_fast_t*)l_branch_temp->data));
        dap_assert_PIF(dap_hash_fast_compare(l_iter->cur_hash, (dap_hash_fast_t*)l_branch_temp->data), "Check adding block into forked branch: ");
    }

    dap_pass_msg("Test of one forked branch ")

    l_chain->callback_atom_iter_delete(l_iter);

    

    


}