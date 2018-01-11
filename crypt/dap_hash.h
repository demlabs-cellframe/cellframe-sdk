#ifndef _DAP_HASH_H_
#define _DAP_HASH_H_
#include <stddef.h>

#include "dap_hash_slow.h"
#include "dap_hash_keccak.h"



typedef enum dap_hash_type {
    DAP_HASH_TYPE_KECCAK = 0,
    DAP_HASH_TYPE_SLOW_0 = 1,
} dap_hash_type_t;

inline void dap_hash(void * a_data_in, size_t a_data_in_size,
                     void * a_data_out, size_t a_data_out_size,
                     dap_hash_type_t a_type ){
    switch (a_type){
        case DAP_HASH_TYPE_KECCAK:
            dap_hash_keccak(a_data_in,a_data_in_size, a_data_out,a_data_out_size);
        break;
        case DAP_HASH_TYPE_SLOW_0:
            if( a_data_out_size>= dap_hash_slow_size() ){
                dap_hash_slow(a_data_in,a_data_in_size,(char*) a_data_out);
            }
        break;
    }

}
#endif
