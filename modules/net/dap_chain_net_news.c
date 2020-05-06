/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2020
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

#include <stddef.h>

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_config.h"

#include "http_status_code.h"
#include "dap_http_simple.h"
#include "dap_enc_http.h"
//#include "<dap_chain_global_db_driver.h>
#include "dap_chain_global_db.h"
#include "dap_chain_net_news.h"
#define LOG_TAG "chain_net_news"

#define NEWS_URL "/news"
#define GROUP_NEWS "cdb.news"
#define DEFAULT_LANG "en"

/* Set news in the selected language
 * a_lang - a language like "en", "ru", "fr"
 * a_data_news - news data
 * a_data_news_len length of news
 */
int dap_chain_net_news_write(char *a_lang, byte_t *a_data_news, size_t a_data_news_len)
{
    if(!a_data_news || !a_data_news_len)
        return -2;
    if(!a_lang)
        a_lang = DEFAULT_LANG;
    size_t l_data_len_out = 0;
    if(dap_chain_global_db_gr_set(a_lang, a_data_news, a_data_news_len, GROUP_NEWS))
        return 0;
    return -1;
}

/* Get news in the selected language
 * a_lang - a language like "en", "ru", "fr"
 */
byte_t* dap_chain_net_news_read(const char *a_lang, size_t *a_news_len)
{
    if(!a_lang)
        return NULL;
    byte_t *l_ret_data = NULL;
    size_t l_data_len_num = 0;
    dap_store_obj_t *l_obj = dap_chain_global_db_obj_gr_get(a_lang, &l_data_len_num, GROUP_NEWS);
    if(l_obj && l_obj->value_len) {
        l_ret_data = DAP_NEW_Z_SIZE(byte_t, l_obj->value_len);
        memcpy(l_ret_data, l_obj->value, l_obj->value_len);
        if(a_news_len)
            *a_news_len = l_obj->value_len;
    }
    dap_store_obj_free(l_obj, l_data_len_num);
    return l_ret_data;
}

/**
 * @brief news_http_proc
 * @param a_http_simple
 * @param a_arg
 */
static void news_http_proc(struct dap_http_simple *a_http_simple, void * a_arg)
{
    log_it(L_DEBUG, "news_http_proc request");
    http_status_code_t * return_code = (http_status_code_t*) a_arg;
    const char *l_lang = DEFAULT_LANG;
    if(dap_strcmp(a_http_simple->http->url_path, NEWS_URL)) {
        l_lang = a_http_simple->http->url_path;
    }

    if(l_lang)
    {
        size_t l_news_data_len = 0;
        // get news in the selected language
        char *l_news_data = dap_chain_net_news_read(l_lang, &l_news_data_len);
        // get news in the default language
        if(!l_news_data && dap_strcmp(a_http_simple->http->in_query_string, "LocalNewsOnly"))
            l_news_data = dap_chain_net_news_read(DEFAULT_LANG, &l_news_data_len);
        a_http_simple->reply = l_news_data ? l_news_data : dap_strdup("no news");
        a_http_simple->reply_size = l_news_data_len;
        *return_code = Http_Status_OK;
    }
    else {
        log_it(L_ERROR, "Wrong request. Must be %s/<lang_code>, example http:/<addr>%s/en", NEWS_URL, NEWS_URL);
        a_http_simple->reply = dap_strdup_printf("Wrong request. Must be %s/<lang_code>, example http:/<addr>%s/en",
        NEWS_URL, NEWS_URL);
        a_http_simple->reply_size = strlen(a_http_simple->reply);
        *return_code = Http_Status_NotFound;
    }
}

/**
 * @brief dap_chain_net_news_add_proc
 * @param sh HTTP server instance
 */
void dap_chain_net_news_add_proc(struct dap_http * sh)
{
    const char * url = NEWS_URL;
    dap_http_simple_proc_add(sh, url, 14096, news_http_proc);
}

