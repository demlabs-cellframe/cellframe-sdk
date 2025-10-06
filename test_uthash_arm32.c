// Minimal test to reproduce ARM32 segfault with uthash
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "uthash.h"

#ifndef DAP_ALIGN_PACKED
#define DAP_ALIGN_PACKED __attribute__((packed))
#endif

#define DAP_HASH_FAST_SIZE 32

// Simulate dap_hash_fast_t
typedef union test_hash {
    uint8_t raw[DAP_HASH_FAST_SIZE];
} DAP_ALIGN_PACKED test_hash_t;

typedef struct test_item {
    test_hash_t my_hash;
    char *name;
    UT_hash_handle hh;       // Handle for table by name
    UT_hash_handle hh_hash;  // Handle for table by my_hash
} test_item_t;

int main() {
    printf("Testing uthash with packed dap_hash_fast_t...\n");
    
    test_item_t *items_by_name = NULL;
    test_item_t *items_by_hash = NULL;
    
    // Create test item
    test_item_t *item = calloc(1, sizeof(test_item_t));
    if (!item) {
        printf("FAIL: allocation\n");
        return 1;
    }
    
    // Initialize fields
    memset(&item->my_hash, 0xAB, sizeof(test_hash_t));
    item->name = strdup("test1");
    
    printf("Adding to hash table by name...\n");
    HASH_ADD_STR(items_by_name, name, item);
    printf("SUCCESS: added by name\n");
    
    printf("Adding to hash table by my_hash...\n");
    printf("sizeof(test_hash_t) = %zu\n", sizeof(test_hash_t));
    printf("offsetof(my_hash) = %zu\n", __builtin_offsetof(test_item_t, my_hash));
    printf("Address of item = %p\n", (void*)item);
    printf("Address of my_hash = %p\n", (void*)&item->my_hash);
    printf("Alignment of my_hash = %zu\n", (size_t)&item->my_hash % 4);
    
    HASH_ADD(hh_hash, items_by_hash, my_hash, sizeof(test_hash_t), item);
    printf("SUCCESS: added by hash\n");
    
    // Try to find
    test_item_t *found = NULL;
    HASH_FIND(hh_hash, items_by_hash, &item->my_hash, sizeof(test_hash_t), found);
    if (found) {
        printf("SUCCESS: found item by hash\n");
    } else {
        printf("FAIL: item not found\n");
    }
    
    printf("Test completed!\n");
    return 0;
}

