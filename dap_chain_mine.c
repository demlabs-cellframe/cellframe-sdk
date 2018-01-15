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

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#define _GNU_SOURCE
#endif

#include <sys/time.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <inttypes.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_chain_block.h"
#include <pthread.h>
#include "dap_chain_mine.h"
#include "dap_chain_mine_task.h"

#define LOG_TAG "dap_chain_mine"

int get_cpu_count()
{
    long nprocs = -1;
    long nprocs_max = -1;
#ifdef _WIN32
  #ifndef _SC_NPROCESSORS_ONLN
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    #define sysconf(a) info.dwNumberOfProcessors
    #define _SC_NPROCESSORS_ONLN
  #endif
#endif
#ifdef _SC_NPROCESSORS_ONLN
    nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs < 1) {
      log_it(L_ERROR, "Could not determine number of CPUs online: %s ", strerror (errno));
      return -1;
    }
    nprocs_max = sysconf(_SC_NPROCESSORS_CONF);
    if (nprocs_max < 1){
      log_it(L_ERROR, "Could not determine number of CPUs configured: %s",strerror (errno));
      return -2;
    }
    log_it(L_INFO, "%ld of %ld processors online",nprocs, nprocs_max);
    return nprocs;
  #else
    log_it(L_ERROR, "Could not determine number of CPUs");
    return -3;
  #endif
}

/**
 * @brief s_mine_thread
 * @param a_arg
 * @return
 */
static void * s_mine_thread(void * a_arg)
{
    dap_chain_mine_task_t * l_task =  (dap_chain_mine_task_t *) a_arg;
    dap_chain_hash_t l_hash;
    dap_chain_hash_kind_t l_hash_kind = HASH_USELESS;
    uint64_t l_difficulty = l_task->block->header.difficulty;
    uint_fast64_t l_nonce;
    uint_fast64_t l_hash_count = 0;
    log_it(L_INFO, "Th#%u:  started",l_task->id);

    // Set CPU affininty and nice level
#ifndef NO_POSIX_SHED
    uint32_t l_cpu_count = get_cpu_count();
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET( l_task->id % l_cpu_count , &mask);

    if ( pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mask) != 0 ){
        log_it(L_CRITICAL, "Error pthread_setaffinity_np() You really have %d or more core in CPU?", l_task->id % l_cpu_count );
        abort();
    }else
        log_it(L_DEBUG, "set affinity to CPU %u", l_task->id % l_cpu_count );

#else
#warning "No SHED affinity, mining could be uneffective"
#endif
    // Set thread priority
    struct sched_param l_prio_param;
    int l_prio_policy=SCHED_RR;
    l_prio_param.__sched_priority= 99;
    pthread_t self_id= pthread_self();
    if( pthread_setschedparam(self_id,l_prio_policy,&l_prio_param)== 0 ){
        log_it(L_DEBUG, "Set priority Round-Robin 99 lvl");
    }else
        log_it(L_WARNING, "Can't set priority to Round-Robin 99 lvl");

    for( l_nonce = l_task->nonce_from ; l_nonce < l_task->nonce_to; ++l_nonce ){
        //log_it(L_DEBUG, "Th#%u: nonce = %llu hash_count = %llu", l_task->id,  l_task->block->header.nonce,
        //       l_hash_count);
        l_task->block->header.nonce = l_nonce;
        dap_chain_block_hash_calc(l_task->block,&l_hash);
        l_hash_count++;

        char l_hash_str[140];
        dap_chain_hash_to_str(&l_hash,l_hash_str,sizeof (l_hash_str) );
        //log_it(L_DEBUG, "Th#%u: block hash %s ",l_task->id, l_hash_str);

        // Update task structure every 10 hashes to prevent often context switch
        if (l_hash_count % 10 == 0){ // TODO Make automatic growing value, depending from hash rate
            atomic_uint_fast64_t l_hash_count_atomic = ATOMIC_VAR_INIT(l_hash_count);
            atomic_exchange(&l_task->hash_count, l_hash_count_atomic);

            if( atomic_load(& l_task->tasks->is_mined) ){
                log_it(L_INFO, "Th#%u: Stop the process", l_task->id);
                break;
            }
        }

        l_hash_kind = dap_chain_hash_kind_check(&l_hash,l_difficulty );
        if (l_task->gold_only){
            if (  l_hash_kind == HASH_GOLD ){
                char l_hash_str[140];
                dap_chain_hash_to_str(&l_hash,l_hash_str,sizeof (l_hash_str) );
                log_it(L_INFO, "Th#%u: !!! Mined GOLD token !!! block hash %s ",l_task->id, l_hash_str);
                break;
            }
        }else if (  l_hash_kind != HASH_USELESS ){
            char l_hash_str[140];
            dap_chain_hash_to_str(&l_hash,l_hash_str,sizeof (l_hash_str) );
            log_it(L_INFO, "Th#%u: !!! Mined SILVER token !!! block hash %s", l_task->id, l_hash_str);
            break;
        }
    }

    if ( l_hash_kind != HASH_USELESS ){
        log_it(L_INFO, "Th#%u: !!! Mined nonce = %" PRIuFAST64 " on try %" PRIuFAST64,l_nonce, l_hash_count );
        atomic_bool l_is_mined_atomic = ATOMIC_VAR_INIT(true);
        atomic_uint_fast64_t l_mined_nonce_atomic = ATOMIC_VAR_INIT(l_nonce);

        memcpy(&l_task->tasks->mined_hash,&l_hash, sizeof(l_task->tasks->mined_hash) );

        atomic_exchange(&l_task->tasks->is_mined, l_is_mined_atomic );
        atomic_exchange(&l_task->tasks->mined_nonce ,l_mined_nonce_atomic);
    }else
        log_it(L_DEBUG, "Th#%u: Mined nothing");

    DAP_DELETE(l_task->block);
    return NULL;
}

static void * s_stats_thread(void * a_arg)
{
    dap_chain_mine_tasks_t * l_tasks =  (dap_chain_mine_tasks_t *) a_arg;

    struct dap_chain_mine_task_result * l_result = DAP_NEW_Z(struct dap_chain_mine_task_result);
    struct timespec l_tm_start;
    struct timespec l_tm_end ;
    clock_gettime(CLOCK_MONOTONIC_RAW,&l_tm_start);
    uint64_t l_tm_diff;
    double l_tm_diff_secs;

    while(true){
        uint_fast64_t l_hash_count_total = 0;
        uint64_t i;
        log_it(L_DEBUG, "Statistic:");

        for( i = 0; i<l_tasks->tasks_count ; ++i){
            //log_it(L_DEBUG, "Thread #%u:  hash_count = %llu", i, atomic_load(&l_tasks->task[i].hash_count));
            l_hash_count_total += atomic_load(& l_tasks->task[i].hash_count );
        }

        clock_gettime(CLOCK_MONOTONIC_RAW,&l_tm_end);
        l_tm_diff =  (l_tm_end.tv_sec - l_tm_start.tv_sec) * 1000000 +  (l_tm_end.tv_nsec - l_tm_start.tv_nsec)/ 1000;
        l_tm_diff_secs = ( (double) l_tm_diff)/ 1000000.0;

        log_it(L_INFO, "Mining time: %04.03lf seconds, %llu hashes, %.03lf H/s ", l_tm_diff_secs
               , l_hash_count_total ,
                ( (double) l_hash_count_total) /  ((double) l_tm_diff_secs ) );
        if(atomic_load(&l_tasks->is_mined) ){
            l_result->success = true;
            l_result->nonce = atomic_load(&l_tasks->mined_nonce);
            memcpy(&l_result->mined_hash, &l_tasks->mined_hash, sizeof(l_tasks->mined_hash) );
            l_result->mined_time = l_tm_diff;
            l_result->hashrate_middle = ( (double) l_hash_count_total) /  ((double) l_tm_diff_secs ) ;
            break;
        }
        sleep(2);
    }
    return l_result;
}


/**
 * @brief dap_chain_mine_block
 * @param a_block_cache
 * @return
 */
int dap_chain_mine_block(dap_chain_block_cache_t * a_block_cache, bool a_mine_gold_only, uint32_t a_threads)
{
    pthread_t stats_pid;
    struct dap_chain_mine_task_result * l_result = NULL;
    dap_chain_mine_tasks_t * l_tasks = DAP_NEW_Z ( dap_chain_mine_tasks_t);

    uint32_t i;

    if( a_threads == 0 ){
        int rval=  get_cpu_count();
        if(rval<0 )
            return -4;
        else
            a_threads = rval;
    }

    l_tasks->task = DAP_NEW_Z_SIZE( struct dap_chain_mine_task, (sizeof(struct dap_chain_mine_task)*a_threads+16) );
    l_tasks->tasks_count = a_threads;
    l_tasks->is_mined = ATOMIC_VAR_INIT(false);
    l_tasks->mined_nonce = ATOMIC_VAR_INIT(0);
    l_tasks->block_cache = a_block_cache;
    uint64_t l_nonce_task_length = UINT64_MAX / a_threads;
    for(i = 0; i< a_threads; i++){ // Creates mining threads
        dap_chain_mine_task_t *l_task = &l_tasks->task[i];
        l_task->tasks = l_tasks;
        l_task->id = i;
        l_task->hash_count = ATOMIC_VAR_INIT(0);
        // Each thread has its own copy of the block for mining
        l_task->block = DAP_NEW_Z_SIZE(dap_chain_block_t,a_block_cache->block->header.size);
        memcpy(l_task->block, a_block_cache->block,a_block_cache->block->header.size );
        // spread nonce between threads
        l_task->nonce_from = i *l_nonce_task_length;
        l_task->nonce_to =  (i==a_threads-1)? UINT64_MAX: (i+1)*l_nonce_task_length;
        pthread_create(& l_task->task_pid ,NULL,s_mine_thread, l_task);
    }
    // Create statistic collector thread
    pthread_create(&stats_pid,NULL,s_stats_thread, l_tasks);

    // Join to it, waiting for results
    pthread_join(stats_pid,(void**) &l_result);
    log_it(L_DEBUG,"Finishing mining threads, free memory...");
    for(i = 0; i< a_threads; i++){ // Creates mining threads
        pthread_join(l_tasks->task[i].task_pid,NULL);
    }

    DAP_DELETE(l_tasks->task);
    //}
    DAP_DELETE (l_tasks);
    if(l_result){
        if(l_result->success){
            log_it(L_INFO,"Mined nonce = 0x%016x Hashrate  %.03lf H/s",l_result->nonce, l_result->hashrate_middle);
            a_block_cache->block->header.nonce = l_result->nonce;
            a_block_cache->block_mine_time = l_result->mined_time;
            memcpy(&a_block_cache->block_hash, &l_result->mined_hash,sizeof(l_result->mined_hash));
            DAP_DELETE(l_result);
            return 0;
        }else{
            log_it(L_INFO,"Minded nothing");
            DAP_DELETE(l_result);
            return 1;
        }
    }else{
        log_it(L_ERROR,"No result! Its NULL!");
        return -2;
    }


}


