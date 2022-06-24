#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "dap_chain_global_db_driver.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_list.h"
#include "dap_chain_common.h"
#include "dap_global_db.h"
#include "dap_global_db_sync.h"


enum    {
    DAP_DB$K_OPTYPE_ADD  = 0x61,    /* 'a', */                              /* Operation Type = INSERT/ADD */
    DAP_DB$K_OPTYPE_DEL  = 0x64,    /* 'd', */                              /*  -- // -- DELETE */
    DAP_DB$K_OPTYPE_RETR = 0x72,    /* 'r', */                              /*  -- // -- RETRIEVE/GET */
};


/**
 * Get entry from base
 */
uint8_t * dap_chain_global_db_gr_get(const char *a_key, size_t *a_data_len_out, const char *a_group);

/**
 * Set one entry to base
 */
bool dap_chain_global_db_gr_set(const char *a_key,  const void *a_value, size_t a_value_len, const char *a_group);


