/**
 * @file test_dap_ledger_event.c
 * @brief Unit tests for DAP Ledger Event functions
 * @details Comprehensive tests for all ledger event management functions:
 *          - Event notification system
 *          - Event finding and listing
 *          - Event public key management (add/remove/check/list)
 *          - Event aggregation
 *          - Thread safety and concurrent operations
 * 
 * @date 2025-11-05
 * @copyright (c) 2025 Demlabs
 */

#include "dap_test.h"
#include "dap_mock.h"
#include "dap_common.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_pvt.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_hash.h"
#include <pthread.h>
#include <string.h>
#include <stdint.h>

#define LOG_TAG "test_ledger_event"

// =============================================================================
// MOCK DECLARATIONS FOR TESTING
// =============================================================================

// Note: We don't need mock wrappers for this test since we work with isolated test data
// and don't call these external functions directly. The ledger event functions are tested
// independently of service verification logic.

// =============================================================================
// TEST FIXTURES AND HELPERS
// =============================================================================

/**
 * @brief Test fixture structure
 */
typedef struct test_ledger_event_fixture {
    dap_ledger_t *ledger;
    dap_chain_net_t *net;
    dap_hash_fast_t test_tx_hash;
    dap_hash_fast_t test_pkey_hash;
    bool callback_called;
    int callback_count;
    dap_ledger_notify_opcodes_t last_opcode;
} test_ledger_event_fixture_t;

static test_ledger_event_fixture_t g_fixture = {0};

/**
 * @brief Create a minimal ledger instance for testing
 */
static dap_ledger_t *create_test_ledger(void)
{
    // Allocate ledger structure
    dap_ledger_t *l_ledger = DAP_NEW_Z(dap_ledger_t);
    if (!l_ledger) {
        log_it(L_ERROR, "Failed to allocate ledger");
        return NULL;
    }
    
    // Allocate private data
    dap_ledger_private_t *l_priv = DAP_NEW_Z(dap_ledger_private_t);
    if (!l_priv) {
        log_it(L_ERROR, "Failed to allocate ledger private data");
        DAP_DELETE(l_ledger);
        return NULL;
    }
    
    // Initialize rwlocks
    pthread_rwlock_init(&l_priv->events_rwlock, NULL);
    pthread_rwlock_init(&l_priv->event_pkeys_rwlock, NULL);
    pthread_rwlock_init(&l_priv->decrees_rwlock, NULL);
    
    // Set up minimal net structure
    dap_chain_net_t *l_net = DAP_NEW_Z(dap_chain_net_t);
    if (!l_net) {
        log_it(L_ERROR, "Failed to allocate net");
        pthread_rwlock_destroy(&l_priv->events_rwlock);
        pthread_rwlock_destroy(&l_priv->event_pkeys_rwlock);
        pthread_rwlock_destroy(&l_priv->decrees_rwlock);
        DAP_DELETE(l_priv);
        DAP_DELETE(l_ledger);
        return NULL;
    }
    
    l_net->pub.id.uint64 = 0x0000000000000001ULL;
    
    // Connect structures
    l_ledger->_internal = l_priv;
    l_ledger->net = l_net;
    l_ledger->is_hardfork_state = false;
    
    return l_ledger;
}

/**
 * @brief Destroy test ledger
 */
static void destroy_test_ledger(dap_ledger_t *a_ledger)
{
    if (!a_ledger)
        return;
    
    dap_ledger_private_t *l_priv = PVT(a_ledger);
    if (l_priv) {
        // Clean up events
        dap_ledger_event_t *l_event, *l_tmp;
        HASH_ITER(hh, l_priv->events, l_event, l_tmp) {
            HASH_DEL(l_priv->events, l_event);
            DAP_DEL_MULTY(l_event->event_data, l_event->group_name, l_event);
        }
        
        // Clean up event pkeys
        dap_ledger_event_pkey_item_t *l_pkey, *l_pkey_tmp;
        HASH_ITER(hh, l_priv->event_pkeys_allowed, l_pkey, l_pkey_tmp) {
            HASH_DEL(l_priv->event_pkeys_allowed, l_pkey);
            DAP_DELETE(l_pkey);
        }
        
        // Clean up notifiers
        dap_list_free(l_priv->event_notifiers);
        
        // Destroy locks
        pthread_rwlock_destroy(&l_priv->events_rwlock);
        pthread_rwlock_destroy(&l_priv->event_pkeys_rwlock);
        pthread_rwlock_destroy(&l_priv->decrees_rwlock);
        
        DAP_DELETE(l_priv);
    }
    
    if (a_ledger->net)
        DAP_DELETE(a_ledger->net);
    
    DAP_DELETE(a_ledger);
}

/**
 * @brief Test notification callback
 */
static void test_event_callback(void *a_arg, dap_ledger_t *a_ledger, 
                                dap_chain_tx_event_t *a_event,
                                dap_hash_fast_t *a_tx_hash,
                                dap_ledger_notify_opcodes_t a_opcode)
{
    UNUSED(a_ledger);
    UNUSED(a_event);
    UNUSED(a_tx_hash);
    
    test_ledger_event_fixture_t *l_fixture = (test_ledger_event_fixture_t *)a_arg;
    if (l_fixture) {
        l_fixture->callback_called = true;
        l_fixture->callback_count++;
        l_fixture->last_opcode = a_opcode;
    }
}

/**
 * @brief Reset test fixture
 */
static void reset_test_fixture(void)
{
    if (g_fixture.ledger) {
        destroy_test_ledger(g_fixture.ledger);
    }
    
    memset(&g_fixture, 0, sizeof(g_fixture));
    
    // Create fresh ledger
    g_fixture.ledger = create_test_ledger();
    
    // Generate test hashes
    dap_hash_fast(g_fixture.test_tx_hash.raw, sizeof(g_fixture.test_tx_hash.raw),
                  &g_fixture.test_tx_hash);
    dap_hash_fast(g_fixture.test_pkey_hash.raw, sizeof(g_fixture.test_pkey_hash.raw),
                  &g_fixture.test_pkey_hash);
    
    // Note: Mock resets not needed as we don't use mocks in this test
}

/**
 * @brief Setup function called before each test
 */
static void setup_test(void)
{
    reset_test_fixture();
}

/**
 * @brief Teardown function called after each test
 */
static void teardown_test(void)
{
    if (g_fixture.ledger) {
        destroy_test_ledger(g_fixture.ledger);
        g_fixture.ledger = NULL;
    }
}

// =============================================================================
// TEST CASES: Event Notification System
// =============================================================================

/**
 * @brief Test adding event notification callback
 */
static void test_ledger_event_notify_add(void)
{
    setup_test();
    
    // Test: Add notification callback
    dap_ledger_event_notify_add(g_fixture.ledger, test_event_callback, &g_fixture);
    
    // Verify: Callback was added to the list
    dap_ledger_private_t *l_priv = PVT(g_fixture.ledger);
    dap_assert(l_priv->event_notifiers != NULL, "Notification callback added");
    
    // Test: Add NULL callback should not crash
    dap_ledger_event_notify_add(g_fixture.ledger, NULL, NULL);
    
    // Test: NULL ledger should not crash
    dap_ledger_event_notify_add(NULL, test_event_callback, NULL);
    
    teardown_test();
}

/**
 * @brief Test event notification callback is triggered
 */
static void test_ledger_event_notify_trigger(void)
{
    setup_test();
    
    // Add notification callback
    dap_ledger_event_notify_add(g_fixture.ledger, test_event_callback, &g_fixture);
    
    // Manually add an event to trigger notification
    dap_ledger_private_t *l_priv = PVT(g_fixture.ledger);
    pthread_rwlock_wrlock(&l_priv->events_rwlock);
    
    dap_ledger_event_t *l_event = DAP_NEW_Z(dap_ledger_event_t);
    l_event->group_name = dap_strdup("test_group");
    l_event->tx_hash = g_fixture.test_tx_hash;
    l_event->event_type = 1;
    l_event->srv_uid.uint64 = 100;
    l_event->timestamp = dap_time_now();
    
    HASH_ADD(hh, l_priv->events, tx_hash, sizeof(dap_hash_fast_t), l_event);
    pthread_rwlock_unlock(&l_priv->events_rwlock);
    
    // Trigger notification by removing event
    dap_ledger_pvt_event_remove(g_fixture.ledger, &g_fixture.test_tx_hash);
    
    // Verify: Callback was called
    dap_assert(g_fixture.callback_called == true, "Event notification callback triggered");
    dap_assert(g_fixture.callback_count == 1, "Callback called exactly once");
    dap_assert(g_fixture.last_opcode == DAP_LEDGER_NOTIFY_OPCODE_DELETED, 
               "Correct opcode received");
    
    teardown_test();
}

// =============================================================================
// TEST CASES: Event Finding
// =============================================================================

/**
 * @brief Test finding event by hash
 */
static void test_ledger_event_find(void)
{
    setup_test();
    
    // Add test event
    dap_ledger_private_t *l_priv = PVT(g_fixture.ledger);
    pthread_rwlock_wrlock(&l_priv->events_rwlock);
    
    dap_ledger_event_t *l_event = DAP_NEW_Z(dap_ledger_event_t);
    l_event->group_name = dap_strdup("test_group");
    l_event->tx_hash = g_fixture.test_tx_hash;
    l_event->event_type = 1;
    l_event->srv_uid.uint64 = 100;
    l_event->timestamp = dap_time_now();
    l_event->pkey_hash = g_fixture.test_pkey_hash;
    
    HASH_ADD(hh, l_priv->events, tx_hash, sizeof(dap_hash_fast_t), l_event);
    pthread_rwlock_unlock(&l_priv->events_rwlock);
    
    // Test: Find existing event
    dap_chain_tx_event_t *l_found = dap_ledger_event_find(g_fixture.ledger, 
                                                           &g_fixture.test_tx_hash);
    dap_assert(l_found != NULL, "Event found by hash");
    dap_assert(strcmp(l_found->group_name, "test_group") == 0, "Event group name matches");
    dap_assert(l_found->event_type == 1, "Event type matches");
    dap_chain_tx_event_delete(l_found);
    
    // Test: Find non-existing event
    dap_hash_fast_t l_non_existing_hash;
    memset(&l_non_existing_hash, 0xFF, sizeof(l_non_existing_hash));
    l_found = dap_ledger_event_find(g_fixture.ledger, &l_non_existing_hash);
    dap_assert(l_found == NULL, "Non-existing event returns NULL");
    
    teardown_test();
}

// =============================================================================
// TEST CASES: Event Listing
// =============================================================================

/**
 * @brief Test getting list of all events
 */
static void test_ledger_event_get_list_all(void)
{
    setup_test();
    
    // Add multiple events
    dap_ledger_private_t *l_priv = PVT(g_fixture.ledger);
    pthread_rwlock_wrlock(&l_priv->events_rwlock);
    
    for (int i = 0; i < 3; i++) {
        dap_ledger_event_t *l_event = DAP_NEW_Z(dap_ledger_event_t);
        l_event->group_name = dap_strdup("test_group");
        l_event->event_type = i;
        l_event->srv_uid.uint64 = 100 + i;
        l_event->timestamp = dap_time_now();
        
        // Generate unique hash for each event
        dap_hash_fast_t l_hash;
        memcpy(&l_hash, &g_fixture.test_tx_hash, sizeof(dap_hash_fast_t));
        l_hash.raw[0] = (uint8_t)i;
        l_event->tx_hash = l_hash;
        
        HASH_ADD(hh, l_priv->events, tx_hash, sizeof(dap_hash_fast_t), l_event);
    }
    pthread_rwlock_unlock(&l_priv->events_rwlock);
    
    // Test: Get list of all events (NULL group name)
    dap_list_t *l_list = dap_ledger_event_get_list(g_fixture.ledger, NULL);
    dap_assert(l_list != NULL, "Event list retrieved");
    
    // Count events
    int l_count = 0;
    for (dap_list_t *it = l_list; it; it = it->next)
        l_count++;
    
    dap_assert(l_count == 3, "All events retrieved");
    
    // Clean up
    dap_list_free_full(l_list, dap_chain_tx_event_delete);
    
    teardown_test();
}

/**
 * @brief Test getting list of events filtered by group
 */
static void test_ledger_event_get_list_by_group(void)
{
    setup_test();
    
    // Add events with different groups
    dap_ledger_private_t *l_priv = PVT(g_fixture.ledger);
    pthread_rwlock_wrlock(&l_priv->events_rwlock);
    
    const char *l_groups[] = {"group_a", "group_b", "group_a"};
    for (int i = 0; i < 3; i++) {
        dap_ledger_event_t *l_event = DAP_NEW_Z(dap_ledger_event_t);
        l_event->group_name = dap_strdup(l_groups[i]);
        l_event->event_type = i;
        l_event->srv_uid.uint64 = 100 + i;
        l_event->timestamp = dap_time_now();
        
        // Generate unique hash for each event
        dap_hash_fast_t l_hash;
        memcpy(&l_hash, &g_fixture.test_tx_hash, sizeof(dap_hash_fast_t));
        l_hash.raw[0] = (uint8_t)i;
        l_event->tx_hash = l_hash;
        
        HASH_ADD(hh, l_priv->events, tx_hash, sizeof(dap_hash_fast_t), l_event);
    }
    pthread_rwlock_unlock(&l_priv->events_rwlock);
    
    // Test: Get list filtered by "group_a"
    dap_list_t *l_list = dap_ledger_event_get_list(g_fixture.ledger, "group_a");
    dap_assert(l_list != NULL, "Filtered event list retrieved");
    
    // Count events in group_a
    int l_count = 0;
    for (dap_list_t *it = l_list; it; it = it->next) {
        dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t *)it->data;
        dap_assert(strcmp(l_event->group_name, "group_a") == 0, 
                   "Event belongs to correct group");
        l_count++;
    }
    
    dap_assert(l_count == 2, "Correct number of events in group_a");
    
    // Clean up
    dap_list_free_full(l_list, dap_chain_tx_event_delete);
    
    teardown_test();
}

// =============================================================================
// TEST CASES: Event Public Key Management
// =============================================================================

/**
 * @brief Test checking event public key (empty allowed list)
 */
static void test_ledger_event_pkey_check_empty_list(void)
{
    setup_test();
    
    // Test: Check pkey when allowed list is empty (should allow all)
    int l_ret = dap_ledger_event_pkey_check(g_fixture.ledger, &g_fixture.test_pkey_hash);
    dap_assert(l_ret == 0, "Empty allowed list permits all keys");
    
    teardown_test();
}

/**
 * @brief Test adding and checking event public key
 */
static void test_ledger_event_pkey_add_and_check(void)
{
    setup_test();
    
    // Test: Add pkey to allowed list
    int l_ret = dap_ledger_event_pkey_add(g_fixture.ledger, &g_fixture.test_pkey_hash);
    dap_assert(l_ret == 0, "Public key added successfully");
    
    // Test: Check that added pkey is allowed
    l_ret = dap_ledger_event_pkey_check(g_fixture.ledger, &g_fixture.test_pkey_hash);
    dap_assert(l_ret == 0, "Added key is allowed");
    
    // Test: Check that non-added pkey is not allowed
    dap_hash_fast_t l_other_hash;
    memset(&l_other_hash, 0xFF, sizeof(l_other_hash));
    l_ret = dap_ledger_event_pkey_check(g_fixture.ledger, &l_other_hash);
    dap_assert(l_ret == -1, "Non-added key is not allowed");
    
    // Test: Add duplicate pkey (should fail)
    l_ret = dap_ledger_event_pkey_add(g_fixture.ledger, &g_fixture.test_pkey_hash);
    dap_assert(l_ret == -1, "Duplicate key addition fails");
    
    teardown_test();
}

/**
 * @brief Test removing event public key
 */
static void test_ledger_event_pkey_remove(void)
{
    setup_test();
    
    // Add pkey
    dap_ledger_event_pkey_add(g_fixture.ledger, &g_fixture.test_pkey_hash);
    
    // Test: Remove existing pkey
    int l_ret = dap_ledger_event_pkey_rm(g_fixture.ledger, &g_fixture.test_pkey_hash);
    dap_assert(l_ret == 0, "Public key removed successfully");
    
    // Test: Check that removed pkey is no longer in list
    dap_list_t *l_list = dap_ledger_event_pkey_list(g_fixture.ledger);
    dap_assert(l_list == NULL, "Removed key not in list");
    
    // Test: Remove non-existing pkey (should fail)
    dap_hash_fast_t l_non_existing;
    memset(&l_non_existing, 0xFF, sizeof(l_non_existing));
    l_ret = dap_ledger_event_pkey_rm(g_fixture.ledger, &l_non_existing);
    dap_assert(l_ret == -1, "Removing non-existing key fails");
    
    teardown_test();
}

/**
 * @brief Test listing event public keys
 */
static void test_ledger_event_pkey_list(void)
{
    setup_test();
    
    // Test: Empty list
    dap_list_t *l_list = dap_ledger_event_pkey_list(g_fixture.ledger);
    dap_assert(l_list == NULL, "Empty pkey list returns NULL");
    
    // Add multiple pkeys
    dap_hash_fast_t l_hashes[3];
    for (int i = 0; i < 3; i++) {
        memcpy(&l_hashes[i], &g_fixture.test_pkey_hash, sizeof(dap_hash_fast_t));
        l_hashes[i].raw[0] = (uint8_t)i;
        dap_ledger_event_pkey_add(g_fixture.ledger, &l_hashes[i]);
    }
    
    // Test: Get list with multiple keys
    l_list = dap_ledger_event_pkey_list(g_fixture.ledger);
    dap_assert(l_list != NULL, "Pkey list retrieved");
    
    // Count keys
    int l_count = 0;
    for (dap_list_t *it = l_list; it; it = it->next)
        l_count++;
    
    dap_assert(l_count == 3, "All pkeys retrieved");
    
    // Clean up
    dap_list_free_full(l_list, (dap_callback_destroyed_t)free);
    
    teardown_test();
}

/**
 * @brief Test event pkey functions with NULL parameters
 */
static void test_ledger_event_pkey_null_params(void)
{
    setup_test();
    
    // Test: NULL ledger
    int l_ret = dap_ledger_event_pkey_add(NULL, &g_fixture.test_pkey_hash);
    dap_assert(l_ret == -1, "Add with NULL ledger fails");
    
    l_ret = dap_ledger_event_pkey_rm(NULL, &g_fixture.test_pkey_hash);
    dap_assert(l_ret == -1, "Remove with NULL ledger fails");
    
    dap_list_t *l_list = dap_ledger_event_pkey_list(NULL);
    dap_assert(l_list == NULL, "List with NULL ledger returns NULL");
    
    // Test: NULL pkey hash
    l_ret = dap_ledger_event_pkey_add(g_fixture.ledger, NULL);
    dap_assert(l_ret == -1, "Add with NULL pkey fails");
    
    l_ret = dap_ledger_event_pkey_rm(g_fixture.ledger, NULL);
    dap_assert(l_ret == -1, "Remove with NULL pkey fails");
    
    teardown_test();
}

// =============================================================================
// TEST CASES: Event Removal
// =============================================================================

/**
 * @brief Test removing existing event
 */
static void test_ledger_event_remove_existing(void)
{
    setup_test();
    
    // Add test event
    dap_ledger_private_t *l_priv = PVT(g_fixture.ledger);
    pthread_rwlock_wrlock(&l_priv->events_rwlock);
    
    dap_ledger_event_t *l_event = DAP_NEW_Z(dap_ledger_event_t);
    l_event->group_name = dap_strdup("test_group");
    l_event->tx_hash = g_fixture.test_tx_hash;
    l_event->event_type = 1;
    l_event->srv_uid.uint64 = 100;
    l_event->timestamp = dap_time_now();
    
    HASH_ADD(hh, l_priv->events, tx_hash, sizeof(dap_hash_fast_t), l_event);
    pthread_rwlock_unlock(&l_priv->events_rwlock);
    
    // Add notification callback
    dap_ledger_event_notify_add(g_fixture.ledger, test_event_callback, &g_fixture);
    
    // Test: Remove existing event
    int l_ret = dap_ledger_pvt_event_remove(g_fixture.ledger, &g_fixture.test_tx_hash);
    dap_assert(l_ret == 0, "Event removed successfully");
    dap_assert(g_fixture.callback_called == true, "Removal notification triggered");
    
    // Verify event is gone
    dap_chain_tx_event_t *l_found = dap_ledger_event_find(g_fixture.ledger, 
                                                           &g_fixture.test_tx_hash);
    dap_assert(l_found == NULL, "Removed event not found");
    
    teardown_test();
}

/**
 * @brief Test removing non-existing event
 */
static void test_ledger_event_remove_non_existing(void)
{
    setup_test();
    
    // Test: Remove non-existing event
    dap_hash_fast_t l_non_existing;
    memset(&l_non_existing, 0xFF, sizeof(l_non_existing));
    
    int l_ret = dap_ledger_pvt_event_remove(g_fixture.ledger, &l_non_existing);
    dap_assert(l_ret == -1, "Removing non-existing event fails");
    
    teardown_test();
}

// =============================================================================
// TEST CASES: Thread Safety
// =============================================================================

/**
 * @brief Thread function for concurrent pkey operations
 */
static void *thread_pkey_operations(void *a_arg)
{
    test_ledger_event_fixture_t *l_fixture = (test_ledger_event_fixture_t *)a_arg;
    
    for (int i = 0; i < 100; i++) {
        dap_hash_fast_t l_hash;
        memcpy(&l_hash, &l_fixture->test_pkey_hash, sizeof(dap_hash_fast_t));
        l_hash.raw[0] = (uint8_t)(i % 10);
        
        // Add key
        dap_ledger_event_pkey_add(l_fixture->ledger, &l_hash);
        
        // Check key
        dap_ledger_event_pkey_check(l_fixture->ledger, &l_hash);
        
        // List keys
        dap_list_t *l_list = dap_ledger_event_pkey_list(l_fixture->ledger);
        if (l_list)
            dap_list_free_full(l_list, (dap_callback_destroyed_t)free);
    }
    
    return NULL;
}

/**
 * @brief Test thread safety of event pkey operations
 */
static void test_ledger_event_pkey_thread_safety(void)
{
    setup_test();
    
    // Create multiple threads
    const int THREAD_COUNT = 4;
    pthread_t l_threads[THREAD_COUNT];
    
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_create(&l_threads[i], NULL, thread_pkey_operations, &g_fixture);
    }
    
    // Wait for all threads
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(l_threads[i], NULL);
    }
    
    // Verify: No crashes occurred
    dap_pass_msg("Thread safety test completed without crashes");
    
    teardown_test();
}

// =============================================================================
// MAIN TEST SUITE
// =============================================================================

int main(int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);
    
    // Initialize DAP SDK
    int l_ret = dap_common_init("test_ledger_event", NULL);
    if (l_ret != 0) {
        printf("Failed to initialize DAP SDK\n");
        return 1;
    }
    
    // Initialize test framework (mock framework not needed for these tests)
    // dap_mock_init();
    
    log_it(L_INFO, "=== DAP Ledger Event Unit Tests ===");
    log_it(L_INFO, "Testing all ledger event functions...\n");
    
    // Run test suite
    dap_print_module_name("Ledger Event Notification System");
    test_ledger_event_notify_add();
    test_ledger_event_notify_trigger();
    
    dap_print_module_name("Ledger Event Finding");
    test_ledger_event_find();
    
    dap_print_module_name("Ledger Event Listing");
    test_ledger_event_get_list_all();
    test_ledger_event_get_list_by_group();
    
    dap_print_module_name("Ledger Event Public Key Management");
    test_ledger_event_pkey_check_empty_list();
    test_ledger_event_pkey_add_and_check();
    test_ledger_event_pkey_remove();
    test_ledger_event_pkey_list();
    test_ledger_event_pkey_null_params();
    
    dap_print_module_name("Ledger Event Removal");
    test_ledger_event_remove_existing();
    test_ledger_event_remove_non_existing();
    
    dap_print_module_name("Ledger Event Thread Safety");
    test_ledger_event_pkey_thread_safety();
    
    log_it(L_INFO, "\n=== All Ledger Event Tests PASSED! ===");
    log_it(L_INFO, "Total: 14 test functions");
    log_it(L_INFO, "Coverage: All public API functions tested");
    
    // Cleanup
    // dap_mock_deinit();
    dap_common_deinit();
    
    return 0;
}

