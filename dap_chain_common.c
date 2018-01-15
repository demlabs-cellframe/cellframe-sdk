#include <string.h>
#include "dap_common.h"
#include "dap_chain_common.h"

#define LOG_TAG "dap_chain_common"

/**
 * @brief dap_chain_hash_to_str
 * @param a_hash
 * @param a_str
 * @param a_str_max
 * @return
 */
size_t dap_chain_hash_to_str(dap_chain_hash_t * a_hash, char * a_str, size_t a_str_max)
{
    const size_t c_hash_str_size = sizeof(*a_hash)*2 +1 /*trailing zero*/ +2 /* heading 0x */  ;
    if (a_str_max < c_hash_str_size ){
        log_it(L_ERROR,"String for hash too small, need %u but have only %u",c_hash_str_size,a_str_max);
    }
    size_t i;
    snprintf(a_str,3,"0x");
    for (i = 0; i< sizeof(a_hash->data); ++i)
        snprintf(a_str+i*2+2,3,"%02x",a_hash->data[i]);
    a_str[c_hash_str_size]='\0';
    return  strlen(a_str);
}
