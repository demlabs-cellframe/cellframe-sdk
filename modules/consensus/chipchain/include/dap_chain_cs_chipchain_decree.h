/**
    * Authors:
    * Dmitrii Gerasimov <dmitry.gerasimov@demlabs.net>
    * Cellframe       https://cellframe.net
    * Copyright  (c) 2026
    * All rights reserved.
 **/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize chipchain decree handlers
 *
 * Registers hardfork and consensus-related decree handlers.
 * @return 0 on success, negative on error
 */
int dap_chain_cs_chipchain_decree_init(void);

/**
 * @brief Deinitialize chipchain decree handlers
 */
void dap_chain_cs_chipchain_decree_deinit(void);

#ifdef __cplusplus
}
#endif
