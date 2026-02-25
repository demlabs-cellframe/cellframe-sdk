/*
 * Authors:
 * Cellframe Team <contact@cellframe.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2025
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

/**
 * @file dap_chain_type_dag_wrap.h
 * @brief Wrapper functions declarations for DAG event operations
 * 
 * These wrapper functions enable mocking via --wrap linker flag.
 * The CLI code calls these wrappers instead of direct functions, allowing tests
 * to intercept the calls.
 * 
 * Similar to block cache wrappers for blocks module.
 */

#pragma once

#include "dap_chain_type_dag.h"
#include "dap_chain_type_dag_event.h"
#include "dap_time.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Wrapper for dap_chain_type_dag_find_event_by_hash
 * 
 * This function is called from CLI code and can be intercepted
 * by --wrap linker flag in unit tests.
 * 
 * @param a_dag Pointer to DAG structure
 * @param a_hash Hash of the event to find
 * @return Pointer to event or NULL if not found
 */
dap_chain_type_dag_event_t *dap_chain_type_dag_find_event_by_hash_w(
    dap_chain_type_dag_t *a_dag,
    dap_chain_hash_fast_t *a_hash);

/**
 * @brief Wrapper for getting events count in DAG
 * 
 * This function is called from CLI code and can be intercepted
 * by --wrap linker flag in unit tests.
 * 
 * @param a_dag Pointer to DAG structure
 * @return Number of events in DAG
 */
uint64_t dap_chain_type_dag_get_events_count_w(dap_chain_type_dag_t *a_dag);

/**
 * @brief Wrapper for getting threshold events count in DAG
 * 
 * This function is called from CLI code and can be intercepted
 * by --wrap linker flag in unit tests.
 * 
 * @param a_dag Pointer to DAG structure
 * @return Number of events in threshold
 */
uint64_t dap_chain_type_dag_get_threshold_count_w(dap_chain_type_dag_t *a_dag);

/**
 * @brief Wrapper for getting last event in DAG
 * 
 * This function is called from CLI code and can be intercepted
 * by --wrap linker flag in unit tests.
 * 
 * @param a_dag Pointer to DAG structure
 * @param a_event_number Output parameter for event number
 * @param a_event_hash Output parameter for event hash
 * @param a_ts_created Output parameter for creation timestamp
 * @return true if last event exists, false otherwise
 */
bool dap_chain_type_dag_get_last_event_w(
    dap_chain_type_dag_t *a_dag,
    uint64_t *a_event_number,
    dap_chain_hash_fast_t *a_event_hash,
    dap_time_t *a_ts_created);

#ifdef __cplusplus
}
#endif


