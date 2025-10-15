/**
 * @file dap_chain_cs_type.h
 * @brief Chain type registration system (blocks, dag, none)
 * 
 * Type = storage/organization of chain data (blocks, dag events, simple list)
 */

#pragma once

#include "dap_chain.h"
#include "dap_config.h"

// Chain type callbacks
typedef int (*dap_chain_callback_new_cfg_t)(dap_chain_t *, dap_config_t *);
typedef int (*dap_chain_callback_t)(dap_chain_t *);

typedef struct dap_chain_type_callbacks {
    dap_chain_callback_new_cfg_t callback_init;
    dap_chain_callback_new_cfg_t callback_load;
    dap_chain_callback_t callback_delete;
    dap_chain_callback_t callback_created;
    dap_chain_callback_t callback_start;
    dap_chain_callback_t callback_stop;
    dap_chain_callback_t callback_purge;
} dap_chain_type_callbacks_t;

// Chain type system initialization
int dap_chain_type_init(void);
void dap_chain_type_deinit(void);

// Chain type registration (blocks, dag, none - storage organization)
void dap_chain_type_add(const char *a_type_str, dap_chain_type_callbacks_t a_callbacks);
int dap_chain_type_create(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
int dap_chain_type_delete(dap_chain_t *a_chain);
int dap_chain_type_purge(dap_chain_t *a_chain);

