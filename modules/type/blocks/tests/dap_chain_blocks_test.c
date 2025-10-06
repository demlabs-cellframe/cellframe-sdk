#include "dap_test.h"
#include "dap_config.h"
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_block.h"
#include "dap_chain_type_blocks.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_type.h"

typedef struct {
    dap_hash_fast_t block_before_fork_hash;
    dap_list_t *reverted_blocks;
    uint64_t reverted_blocks_cnt;
    uint64_t main_blocks_cnt;
} last_fork_resolved_notification_data_t;

static dap_hash_fast_t s_last_confirmed_block_hash = {};
static dap_hash_fast_t s_last_notified_block_hash = {};
static int s_confirmed_blocks_counter = 0;
static int s_custom_notify_counter = 0;

static last_fork_resolved_notification_data_t s_fork_resolved_arg = {};

typedef struct {
    dap_hash_fast_t *last_notified_hash;
    int *cnt;
} notify_arg_t;

void callback_notify(void *a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id, dap_chain_hash_fast_t *a_atom_hash, void *a_atom, size_t a_atom_size, dap_time_t a_atom_time)
{
    notify_arg_t *l_arg = (notify_arg_t*)a_arg; 
    (*l_arg->cnt)++;
    *l_arg->last_notified_hash = *a_atom_hash;
}

static void *s_callback_list_copy(const void *a_data, UNUSED_ARG void *a_usr_data)
{
    return DAP_DUP((dap_hash_fast_t *)a_data);
}

void callback_fork_resolved_notify(dap_chain_t *a_chain, dap_hash_fast_t a_block_before_fork_hash, dap_list_t *a_reverted_blocks, 
                                                                uint64_t a_reverted_blocks_cnt, uint64_t a_main_blocks_cnt, void * a_arg)
{
    last_fork_resolved_notification_data_t *l_arg = (last_fork_resolved_notification_data_t*)a_arg;
    
    l_arg->reverted_blocks = dap_list_copy_deep(a_reverted_blocks, s_callback_list_copy, NULL);
    l_arg->main_blocks_cnt = a_main_blocks_cnt;
    l_arg->reverted_blocks_cnt = a_reverted_blocks_cnt;
    l_arg->block_before_fork_hash = a_block_before_fork_hash;
}

dap_hash_fast_t dap_chain_block_test_add_new_block (dap_hash_fast_t *a_prev_block_hash, dap_chain_t *a_chain, dap_chain_block_t **a_block, size_t *a_block_size)
{
    size_t l_block_size = 0;
    dap_hash_fast_t l_block_hash = {};
    dap_chain_block_t * l_block = dap_chain_block_new(a_prev_block_hash, &l_block_size);
    dap_assert_PIF(l_block != NULL, "Creating of block:");
    dap_hash_fast(l_block, l_block_size, &l_block_hash);
    dap_chain_atom_verify_res_t ret_val = a_chain->callback_atom_add(a_chain, (dap_chain_atom_ptr_t)l_block, l_block_size, &l_block_hash, false);
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
        l_branch_temp = l_branch_temp->next, l_atom = a_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size_from_iter)) {
        char l_branch_hash_str[DAP_HASH_FAST_STR_SIZE];
        dap_hash_fast_to_str((dap_hash_fast_t *)l_branch_temp->data, l_branch_hash_str, DAP_HASH_FAST_STR_SIZE);
        dap_test_msg("Check block %s : num %" DAP_UINT64_FORMAT_U " and %s", dap_chain_hash_fast_to_str_static(l_iter->cur_hash), l_iter->cur_num, l_branch_hash_str);
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
    dap_assert_PIF(dap_chain_type_blocks_init() == 0, "Initialization of dap consensus block: ");

    dap_assert_PIF(dap_chain_cs_esbocs_init() == 0, "Initialization of esbocs: ");

    const char *l_chain_net_name = "testnet";
    const char *l_chain_name = "testchain";
    dap_chain_net_id_t l_chain_net_id = {.uint64 = 1}; 
    dap_chain_id_t l_chain_id = {.uint64 = 1};

    dap_chain_t *l_chain =  dap_chain_create(l_chain_net_name, l_chain_name, l_chain_net_id, l_chain_id);
    l_chain->config = dap_config_create_empty();
    dap_config_set_item_str(l_chain->config, "chain", "consensus", "esbocs");
    dap_assert_PIF(dap_chain_cs_create(l_chain, l_chain->config) == 0, "Chain cs creating: ");


    notify_arg_t *l_arg = DAP_NEW_Z(notify_arg_t);
    l_arg->cnt = &s_confirmed_blocks_counter;
    l_arg->last_notified_hash = &s_last_confirmed_block_hash;
    dap_chain_atom_confirmed_notify_add(l_chain, callback_notify, (void*)l_arg, 0);
    l_arg = DAP_NEW_Z(notify_arg_t);
    l_arg->cnt = &s_custom_notify_counter;
    l_arg->last_notified_hash = &s_last_notified_block_hash;
    dap_chain_atom_confirmed_notify_add(l_chain, callback_notify, (void*)l_arg, 2);

    dap_chain_block_add_fork_notificator(callback_fork_resolved_notify, &s_fork_resolved_arg);

    dap_hash_fast_t l_forked_block_hash = {};
    dap_hash_fast_t l_block_hash = {};
    dap_hash_fast_t l_genesis_block_hash = {};

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
    l_genesis_block_hash = l_block_hash;
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


    dap_assert_PIF((s_custom_notify_counter == 1 && dap_hash_fast_compare(&s_last_notified_block_hash, &l_genesis_block_hash)), "Check custom notify: ");
    
    l_block_hash = dap_chain_block_test_add_new_block (&l_block_hash, l_chain, &l_block_repeat_middle_forked, &l_block_repeat_middle_forked_size);
    l_block_repeat_middle_forked_hash = l_block_hash;
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_first_branch_atoms_list = dap_list_append(l_first_branch_atoms_list, l_block_hash_copy);

    dap_assert_PIF((s_custom_notify_counter == 2 && dap_hash_fast_compare(&s_last_notified_block_hash, &l_forked_block_hash)), "Check custom notify: ");

    dap_chain_atom_verify_res_t ret_val = l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block_double_main_branch, l_block_double_main_branch_size, &l_block_double_main_branch_hash, false);
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

    ret_val = l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block_repeat_first_forked, l_block_repeat_first_forked_size, &l_block_repeat_first_forked_hash, false);
    dap_assert_PIF(ret_val == ATOM_PASS, "Add existing first forked block into chain. Must be passed: ");

    dap_test_msg("Add third atom to the forked branch...");
    l_block_hash = dap_chain_block_test_add_new_block (&l_block_hash, l_chain, NULL, NULL);
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_second_branch_atoms_list = dap_list_append(l_second_branch_atoms_list, l_block_hash_copy);

    dap_assert_PIF(dap_chain_block_test_compare_chain_hash_lists(l_chain, l_second_branch_atoms_list), "Check branches is switched: ");
    dap_assert_PIF(dap_hash_fast_compare(&s_fork_resolved_arg.block_before_fork_hash, &l_forked_block_hash) && 
                    s_fork_resolved_arg.main_blocks_cnt == 3 && s_fork_resolved_arg.reverted_blocks_cnt == 2, "Check branches is switched notification: ");

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


    dap_hash_fast_t l_last_former_main_branch_hash = l_block_hash;

    // genesis block must be confirmed, check counter and hash of confirmed block
    dap_assert_PIF((s_confirmed_blocks_counter == 1 && dap_hash_fast_compare(&s_last_confirmed_block_hash, &l_genesis_block_hash)), "Check confirmed block: ");

    /* ========================== Add second forked branch ======================= */
    dap_test_msg("Add atom to second forked branch...");
    l_block_hash = dap_chain_block_test_add_new_block (&l_forked_block_hash, l_chain, NULL, NULL);
    dap_hash_fast_t l_third_confirmed_block = l_block_hash;
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

    // second block must be confirmed, check counter and hash of confirmed block
    dap_assert_PIF((s_confirmed_blocks_counter == 2 && dap_hash_fast_compare(&s_last_confirmed_block_hash, &l_forked_block_hash)), "Check confirmed block: ");

    ret_val = l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block_repeat_middle_forked, l_block_repeat_middle_forked_size, &l_block_repeat_middle_forked_hash, false);
    dap_assert_PIF(ret_val == ATOM_PASS, "Add existing block into middle of forked chain. Must be passed: ");

    dap_test_msg("Add 6th atom to second forked branch...");
    l_block_hash = dap_chain_block_test_add_new_block (&l_block_hash, l_chain, NULL, NULL);
    l_block_hash_copy = DAP_DUP(&l_block_hash);
    l_third_branch_atoms_list = dap_list_append(l_third_branch_atoms_list, l_block_hash_copy);

     // third block must be confirmed, check counter and hash of confirmed block
    dap_assert_PIF((s_confirmed_blocks_counter == 3 && dap_hash_fast_compare(&s_last_confirmed_block_hash, &l_third_confirmed_block)), "Check confirmed block: ");

    // dap_test_msg("Add new block into former main chain...");
    // size_t l_block_size = 0;
    // dap_chain_block_t * l_block = dap_chain_block_new(&l_last_former_main_branch_hash, &l_block_size);
    // dap_assert_PIF(l_block != NULL, "Creating of block:");
    // dap_hash_fast(l_block, l_block_size, &l_block_hash);
    // ret_val = l_chain->callback_atom_add(l_chain, (dap_chain_atom_ptr_t)l_block, l_block_size, &l_block_hash, false);
    // dap_assert_PIF(ret_val == ATOM_REJECT, "Add new block into former main chain. Must be rejected because this fork is deeper max than depth: ");

    dap_pass_msg("Fork handling test: ");
}
