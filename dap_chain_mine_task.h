/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include "dap_chain_common.h"
#include "dap_chain_block.h"
#include "dap_chain_block_cache.h"

typedef struct dap_chain_mine_task
{
    uint32_t id;
    pthread_t task_pid;
    uint64_t nonce_from;
    uint64_t nonce_to;
    atomic_uint_fast64_t hash_count;
    bool gold_only;
    dap_chain_block_t * block;
    struct  dap_chain_mine_tasks * tasks;
} dap_chain_mine_task_t;

typedef struct  dap_chain_mine_tasks{
    atomic_bool is_mined;
    uint32_t tasks_count;
    atomic_uint_fast64_t mined_nonce;
    struct  dap_chain_mine_task * task;
    dap_chain_hash_t mined_hash;
    double hashrate_prev[10];
    double hashrate_avg;
    dap_chain_block_cache_t * block_cache;
} dap_chain_mine_tasks_t;

struct dap_chain_mine_task_result
{
    bool success;
    uint64_t nonce;
    double mined_time;
    double hashrate_middle;
    dap_chain_hash_t mined_hash;
};
