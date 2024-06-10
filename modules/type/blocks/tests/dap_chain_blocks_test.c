#include "dap_test.h"
#include "dap_config.h"
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_block.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_cs.h"
// #include "dap_chain_cs_blocks.h"

dap_hash_fast_t dap_chain_block_test_add_new_block (dap_hash_fast_t *a_prev_block_hash, dap_chain_t *a_chain, dap_chain_block_t **a_block, size_t *a_block_size)
{
    size_t l_block_size = 0;
    dap_hash_fast_t l_block_hash = {};
    dap_chain_block_t * l_block = dap_chain_block_new(a_prev_block_hash, &l_block_size);
    dap_assert_PIF(l_block != NULL, "Creating of block:");
    dap_hash_fast(l_block, l_block_size, &l_block_hash);
    dap_chain_atom_verify_res_t ret_val = a_chain->callback_atom_add(a_chain, (dap_chain_atom_ptr_t)l_block, l_block_size, &l_block_hash);
    dap_assert_PIF( (ret_val == ATOM_ACCEPT || ret_val == ATOM_FORK), "Add block into chain: ");

    if (a_block)
        *a_block = l_block;

    if(a_block_size)
        *a_block_size = l_block_size;

    return l_block_hash;
}

bool dap_chain_block_test_compare_chain_hash_lists(dap_chain_t* a_chain, dap_list_t* a_atoms_hash_list)
{
    dap_chain_cell_id_t l_cell_id = {.uint64 = 1};
    size_t l_atom_size_from_iter = 0;
    dap_chain_atom_iter_t *l_iter = a_chain->callback_atom_iter_create(a_chain, l_cell_id, NULL);
    dap_list_t *l_branch_temp = NULL;
    dap_chain_atom_ptr_t l_atom = a_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_FIRST, &l_atom_size_from_iter);
    for (dap_list_t *l_branch_temp = a_atoms_hash_list; l_branch_temp && l_atom; 
        l_branch_temp = l_branch_temp->next, l_atom = a_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size_from_iter)){
        dap_test_msg("Check block %s : num %d and %s", dap_chain_hash_fast_to_str_static(l_iter->cur_hash), l_iter->cur_num,
                                            dap_chain_hash_fast_to_str_static((dap_hash_fast_t*)l_branch_temp->data));
        if (!dap_hash_fast_compare(l_iter->cur_hash, (dap_hash_fast_t*)l_branch_temp->data)){
            a_chain->callback_atom_iter_delete(l_iter);
            return false;
        }

    }
    a_chain->callback_atom_iter_delete(l_iter);
    return true;
}

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

    dap_hash_fast_t l_forked_block_hash = {};
    dap_hash_fast_t l_block_hash = {};

    dap_chain_block_t *l_block_repeat_first_forked = NULL;
    dap_chain_block_t *l_block_double_main_branch = NULL;
    dap_chain_block_t *l_block_repeat_middle_forked = NULL;
    dap_chain_block_t *l_block_middle_prev_forked = NULL;
    dap_hash_fast_t l_block_repeat_first_forked_hash = {};
    dap_hash_fast_t l_block_double_main_branch_hash = {};
    dap_hash_fast_t l_block_repeat_middle_forked_hash = {};
    dap_hash_fast_t l_block_middle_prev_forked_hash = {};

    size_t l_block_repeat_first_forked_size = 0;
    size_t l_block_double_main_branch_size = 0;
    size_t l_block_repeat_middle_forked_size = 0;
    size_t l_block_middle_prev_forked_size = 0;

    dap_list_t *l_first_branch_atoms_list = NULL;
    dap_list_t *l_second_branch_atoms_list = NULL;
    dap_list_t *l_third_branch_atoms_list = NULL;

    dap_test_msg("Add genesis block...");
    l_block_hash = dap_chain_block_test_add_new_block (NULL, l_chain, NULL, NULL);
    dap_hash_fast_t *l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);
    l_second_branch_atoms_list = dap_list_append(l_second_branch_atoms_list, l_block_hash_copy);
    l_third_branch_atoms_list = dap_list_append(l_third_branch_atoms_list, l_block_hash_copy);

    dap_test_msg("Add second block...");
    l_block_hash = dap_chain_block_test_add_new_block (&l_block_hash, l_chain, NULL, NULL);
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);
    l_second_branch_atoms_list = dap_list_append(l_second_branch_atoms_list, l_block_hash_copy);
    l_third_branch_atoms_list = dap_list_append(l_third_branch_atoms_list, l_block_hash_copy);
    l_forked_block_hash = l_block_hash;

    dap_test_msg("Add 2 blocks to main branch...");
    l_block_hash = dap_chain_block_test_add_new_block (&l_block_hash, l_chain, &l_block_double_main_branch, &l_block_double_main_branch_size);
    l_block_double_main_branch_hash = l_block_hash;
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);


    l_block_hash = dap_chain_block_test_add_new_block (&l_block_hash, l_chain, &l_block_repeat_middle_forked, &l_block_repeat_middle_forked_size);
    l_block_repeat_middle_forked_hash = l_block_hash;
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);

    dap_chain_atom_verify_res_t ret_val = l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block_double_main_branch, l_block_double_main_branch_size, &l_block_double_main_branch_hash);
    dap_assert_PIF(ret_val == ATOM_PASS, "Add existing block into middle of main chain. Must be passed: ");
    
    dap_assert_PIF(dap_chain_block_test_compare_chain_hash_lists(l_chain, l_first_branch_atoms_list), "Check chain after atoms adding to the main branch ");

    /* ========================== Forked branches testing ======================= */
    /* ========================== Add first forked branch ======================= */
    dap_test_msg("Add forked branch...");
    l_block_hash = dap_chain_block_test_add_new_block (&l_forked_block_hash, l_chain, &l_block_repeat_first_forked, &l_block_repeat_first_forked_size);
    l_block_repeat_first_forked_hash = l_block_hash;
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_second_branch_atoms_list = dap_list_append(l_second_branch_atoms_list, l_block_hash_copy);

    dap_test_msg("Add second atom to the forked branch...");
    l_block_hash = dap_chain_block_test_add_new_block (&l_block_hash, l_chain, &l_block_repeat_middle_forked, &l_block_repeat_middle_forked_size);
    l_block_repeat_middle_forked_hash = l_block_hash;
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_second_branch_atoms_list = dap_list_append(l_second_branch_atoms_list, l_block_hash_copy);

    dap_assert_PIF(dap_chain_block_test_compare_chain_hash_lists(l_chain, l_first_branch_atoms_list), "Check branches is not switched: ");

    ret_val = l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block_repeat_first_forked, l_block_repeat_first_forked_size, &l_block_repeat_first_forked_hash);
    dap_assert_PIF(ret_val == ATOM_PASS, "Add existing first forked block into chain. Must be passed: ");

    dap_test_msg("Add third atom to the forked branch...");
    l_block_hash = dap_chain_block_test_add_new_block (&l_block_hash, l_chain, NULL, NULL);
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_second_branch_atoms_list = dap_list_append(l_second_branch_atoms_list, l_block_hash_copy);

    dap_assert_PIF(dap_chain_block_test_compare_chain_hash_lists(l_chain, l_second_branch_atoms_list), "Check branches is switched: ");

    dap_test_msg("Add block to former main branch");
    l_block_hash = dap_chain_block_test_add_new_block ((dap_hash_fast_t*)dap_list_last(l_first_branch_atoms_list)->data, l_chain, NULL, NULL);
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);

    dap_assert_PIF(dap_chain_block_test_compare_chain_hash_lists(l_chain, l_second_branch_atoms_list), "Check branches is not switched: ");


    dap_test_msg("Add another block to former main branch");
    l_block_hash = dap_chain_block_test_add_new_block (&l_block_hash, l_chain, NULL, NULL);
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);

    dap_assert_PIF(dap_chain_block_test_compare_chain_hash_lists(l_chain, l_first_branch_atoms_list), "Check branches is switched: ");


    /* ========================== Add second forked branch ======================= */
    dap_test_msg("Add atom to second forked branch...");
    l_block_hash = dap_chain_block_test_add_new_block (&l_forked_block_hash, l_chain, NULL, NULL);
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_third_branch_atoms_list = dap_list_append(l_third_branch_atoms_list, l_block_hash_copy);

    for (int i = 0; i < 3; i++){
        dap_test_msg("Add atom to second forked branch...");
        l_block_hash = dap_chain_block_test_add_new_block (&l_block_hash, l_chain, NULL, NULL);
        l_block_hash_copy = DAP_DUP(&l_block_hash);
        l_third_branch_atoms_list = dap_list_append(l_third_branch_atoms_list, l_block_hash_copy);
    }

    dap_assert_PIF(dap_chain_block_test_compare_chain_hash_lists(l_chain, l_first_branch_atoms_list), "Check branches is not switched: ");

    dap_test_msg("Add 5th atom to second forked branch...");
    l_block_hash = dap_chain_block_test_add_new_block (&l_block_hash, l_chain, NULL, NULL);
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_third_branch_atoms_list = dap_list_append(l_third_branch_atoms_list, l_block_hash_copy);

    dap_assert_PIF(dap_chain_block_test_compare_chain_hash_lists(l_chain, l_third_branch_atoms_list), "Check branches is switched: ");

    
    ret_val = l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block_repeat_middle_forked, l_block_repeat_middle_forked_size, &l_block_repeat_middle_forked_hash);
    dap_assert_PIF(ret_val == ATOM_PASS, "Add existing block into middle of forked chain. Must be passed: ");

    dap_pass_msg("Fork handling test: ")
}