/**
 * @file dap_chain_cs_class.h
 * @brief Consensus class registration system (old architecture)
 */

#pragma once

#include "dap_chain.h"
#include "dap_config.h"

// Consensus class callbacks (for registering consensus implementations like esbocs, dag-poa)
typedef int (*dap_chain_callback_new_cfg_t)(dap_chain_t *, dap_config_t *);
typedef int (*dap_chain_callback_t)(dap_chain_t *);

typedef struct dap_chain_cs_class_callbacks {
    dap_chain_callback_new_cfg_t callback_init;
    dap_chain_callback_t callback_delete;
    dap_chain_callback_t callback_purge;
} dap_chain_cs_class_callbacks_t;

// Old consensus callbacks structure (different from new dap_chain_cs_callbacks_t in dap_chain.h!)
typedef struct dap_chain_cs_old_callbacks {
    dap_chain_callback_new_cfg_t callback_init;
    dap_chain_callback_new_cfg_t callback_load;
    dap_chain_callback_t callback_stop;
    dap_chain_callback_t callback_start;
    dap_chain_callback_t callback_purge;
} dap_chain_cs_old_callbacks_t;

// Functions for old consensus registration system
int dap_chain_cs_init(void);
void dap_chain_cs_deinit(void);

void dap_chain_cs_class_add(const char *a_cs_str, dap_chain_cs_class_callbacks_t a_callbacks);
int dap_chain_cs_class_create(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
int dap_chain_cs_class_delete(dap_chain_t *a_chain);
int dap_chain_cs_class_purge(dap_chain_t *a_chain);

void dap_chain_cs_add(const char *a_cs_str, dap_chain_cs_old_callbacks_t a_callbacks);
int dap_chain_cs_create(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
int dap_chain_cs_load(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
int dap_chain_cs_stop(dap_chain_t *a_chain);
int dap_chain_cs_start(dap_chain_t *a_chain);
int dap_chain_cs_purge(dap_chain_t *a_chain);

