#include "dap_common.h"
#include "dap_http_client.h"
#include "dap_http_simple.h"
#include "dap_chain_mempool.h"

/**
 * @brief
 * @param cl_st HTTP server instance
 * @param arg Not used
 */
void chain_mempool_proc(struct dap_http_simple *cl_st, void * arg)
{

}

/**
 * @brief chain_mempool_add_proc
 * @param sh HTTP server instance
 * @param url URL string
 */
void dap_chain_mempool_add_proc(struct dap_http * sh, const char * url)
{
    /*void dap_http_simple_proc_add(dap_http_t *sh, const char * url_path, size_t reply_size_max, dap_http_simple_callback_t cb); // Add simple processor*/
    dap_http_simple_proc_add(sh, url, 4096, chain_mempool_proc);
}
