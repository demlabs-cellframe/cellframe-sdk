#include <time.h>
#include "dap_common.h"
#include "dap_chain_block.h"
#include "dap_chain_mine.h"

#define LOG_TAG "dap_chain_mine"

/**
 * @brief dap_chain_mine_block
 * @param a_block_cache
 * @return
 */
int dap_chain_mine_block(dap_chain_block_cache_t * a_block_cache, bool a_mine_gold_only)
{
    dap_chain_hash_t l_hash;
    dap_chain_block_t * l_block = a_block_cache->block;
    dap_chain_hash_kind_t l_hash_kind;
    uint64_t l_difficulty = l_block->header.difficulty;
    time_t l_tm_start = time(NULL);
    uint64_t l_hash_count = 0;
    do{
        l_block->header.nonce++;
        log_it(L_DEBUG,"nonce %llu",l_block->header.nonce);
        dap_chain_block_hash_calc(l_block,&l_hash);
        l_hash_count++;
        l_hash_kind = dap_chain_hash_kind_check(&l_hash,l_difficulty );
        if(l_block->header.nonce = 0x0fffffffffffffff )
            break;
        if (a_mine_gold_only){
            if (  l_hash_kind != HASH_GOLD ){
                continue;
            }
        }
    }while (  l_hash_kind == HASH_USELESS );
    time_t l_tm_end = time(NULL);
    if ( l_hash_kind == HASH_GOLD ){
        log_it(L_INFO, " !!! Mined GOLD token !!!");
    }else if ( l_hash_kind == HASH_SILVER ) {
        log_it(L_INFO, " !!! Mined SILVER token !!!");
    }
    log_it(L_DEBUG, "Mining time: %lu seconds, %llu hashes, %llu H/s ", l_tm_end - l_tm_start,l_hash_count,
            l_hash_count / (l_tm_end - l_tm_start));
    return l_hash_kind != HASH_USELESS;
}
