/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.        https://demlabs.net
 * CellFrame            https://cellframe.net
 * Sources              https://gitlab.demlabs.net/cellframe
 * Cellframe CDB lib    https://gitlab.demlabs.net/dap.support/cellframe-node-cdb-lib
 * Copyrighted by Demlabs Limited, 2020
 * All rights reserved.
 */

#include <stddef.h>
#include <json-c/json.h>
#include <json-c/json_object.h>

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_config.h"
#include "dap_chain_node_cli.h"
#include "rand/dap_rand.h"

#include "http_status_code.h"
#include "dap_http_simple.h"
#include "dap_enc_http.h"
//#include "<dap_chain_global_db_driver.h>
#include "dap_chain_global_db.h"
#include "dap_chain_net_news.h"
#include "dap_chain_net_srv_vpn_cdb.h"
#define LOG_TAG "cdb_news"

#define NEWS_URL "/news"
#define GROUP_NEWS "cdb.news"
#define DEFAULT_LANG "en"

static dap_http_url_proc_t * s_url_proc = NULL;
static time_t s_cache_expire = 3600;

int com_news(int a_argc, char ** a_argv, void *a_arg_func, char **a_str_reply);
int dap_chain_net_news_write(const char *a_lang, char *a_data_news, size_t a_data_news_len);
byte_t* dap_chain_net_news_read(const char *a_lang, size_t *a_news_len);
void dap_chain_net_news_add_proc(struct dap_http * sh);

int dap_chain_net_news_init(dap_http_t * a_http)
{
    s_cache_expire = dap_config_get_item_int32_default(g_dap_config_cdb, "cdb","cache_expire", s_cache_expire);

    dap_chain_node_cli_cmd_item_create("news", com_news, NULL, "Add News for VPN clients. Language code is a text code like \"en\", \"ru\", \"fr\"",
            "news [-text <news text> | -file <filename with news>] -lang <language code> \n");
    dap_chain_net_news_add_proc(a_http);

    return 0;
}

/**
 * Add News for VPN clients
 * news [-text <news text> | -file <filename with news>] -lang <language code>
 */
int com_news(int a_argc, char ** a_argv, void *a_arg_func, char **a_str_reply)
{
    int arg_index = 1;
    const char * l_str_lang = NULL;
    const char * l_str_text = NULL;
    const char * l_str_file = NULL;

    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-lang", &l_str_lang);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-text", &l_str_text);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-file", &l_str_file);

    if(!l_str_text && !l_str_file) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "no source of news, add parameter -text or -file");
        return -1;
    }
    char *l_data_news;
    size_t l_data_news_len = 0;
    const char *l_from = NULL;

    if(l_str_text) {
        l_data_news = dap_strdup(l_str_text);
        l_data_news_len = dap_strlen(l_str_text);
        l_from = "text";
    }
    else if(l_str_file) {
        if(dap_file_get_contents(l_str_file, &l_data_news,&l_data_news_len)) {
            l_from = "file";
        }
        else{
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't read file %s", l_str_file);
                return -2;
            }
    }

    int l_res = dap_chain_net_news_write(l_str_lang, l_data_news, l_data_news_len);
    if(l_res){
        dap_chain_node_cli_set_reply_text(a_str_reply, "Error, News cannot be added from %s", l_from);
        return -3;
    }
    dap_chain_node_cli_set_reply_text(a_str_reply, "News added from %s successfully", l_from);
    return 0;
}


char* dap_chain_net_news_added_extra_info(const char *a_json_text)
{
    // parse existing news in json format
    struct json_object *l_jobj_arr = json_tokener_parse(a_json_text);
    if(json_object_is_type(l_jobj_arr, json_type_array)) {
        int64_t l_timestamp = time(NULL);
        // news may consist of several news blocks
        size_t l_size = json_object_array_length(l_jobj_arr);
        for(int i = 0; i < (int) l_size; i++) {
            json_object *l_one_news = json_object_array_get_idx(l_jobj_arr, i);
            if(json_object_is_type(l_one_news, json_type_object)) {
                // add timestamp
                json_object_object_add(l_one_news, "timestamp", json_object_new_int64(l_timestamp));
                // create unique number for news
                uint64_t l_id;
                randombytes(&l_id, sizeof(int64_t));
                l_id %= 100000ll; //l_id 5 characters long
                // add unique id
                json_object_object_add(l_one_news, "id", json_object_new_int64(l_id));
            }
        }

        char* json_str = dap_strdup(json_object_to_json_string(l_jobj_arr));
        json_object_put(l_jobj_arr);
        return json_str;
    }
    return NULL;
}

/* Set news in the selected language
 * a_lang - a language like "en", "ru", "fr"
 * a_data_news - news data
 * a_data_news_len length of news
 */
int dap_chain_net_news_write(const char *a_lang, char *a_data_news, size_t a_data_news_len)
{
    if(!a_data_news || !a_data_news_len)
        return -2;
    if(!a_lang)
        a_lang = DEFAULT_LANG;
    // insert timestamp and id into news
    char *l_data_news_new = dap_chain_net_news_added_extra_info(a_data_news);
    if(l_data_news_new){
        size_t l_data_news_new_len = dap_strlen(l_data_news_new);
        if(dap_chain_global_db_gr_set((char *)a_lang, l_data_news_new, l_data_news_new_len, GROUP_NEWS))
            return 0;
    }
    if(dap_chain_global_db_gr_set((char *)a_lang, a_data_news, a_data_news_len, GROUP_NEWS))
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
    if(dap_strcmp(a_http_simple->http_client->url_path, NEWS_URL)) {
        l_lang = a_http_simple->http_client->url_path;
    }

    if(l_lang)
    {
        size_t l_news_data_len = 0;
        // get news in the selected language
        byte_t *l_news_data = dap_chain_net_news_read(l_lang, &l_news_data_len);
        // get news in the default language
        if(!l_news_data && dap_strcmp(a_http_simple->http_client->in_query_string, "LocalNewsOnly"))
            l_news_data = dap_chain_net_news_read(DEFAULT_LANG, &l_news_data_len);
        if(!l_news_data){
            a_http_simple->reply = l_news_data ;
            a_http_simple->reply_size = l_news_data_len;
        }else{
            a_http_simple->reply = dap_strdup("[{ \"message\": \"no news\"}]");
            a_http_simple->reply_size = dap_strlen((char*) a_http_simple->reply);
        }
        *return_code = Http_Status_OK;
    }
    else {
        log_it(L_ERROR, "Wrong request. Must be %s/<lang_code>, example http:/<addr>%s/en", NEWS_URL, NEWS_URL);
        a_http_simple->reply = dap_strdup_printf("[{ \"error\": \"Wrong request. Must be %s/<lang_code>, example http:/<addr>%s/en\"}]", NEWS_URL, NEWS_URL);
        a_http_simple->reply_size = strlen(a_http_simple->reply);
        *return_code = Http_Status_OK;//Http_Status_NotFound;
    }
    strcpy(a_http_simple->reply_mime, "application/json");
    dap_http_simple_make_cache_from_reply(a_http_simple,time(NULL)+ s_cache_expire);
}

/**
 * @brief dap_chain_net_news_add_proc
 * @param sh HTTP server instance
 */
void dap_chain_net_news_add_proc(struct dap_http * sh)
{
    const char * url = NEWS_URL;
    s_url_proc = dap_http_simple_proc_add(sh, url, 14096, news_http_proc);
}


/**
 * @brief dap_chain_net_srv_vpn_cdb_news_cache_reset
 */
void dap_chain_net_srv_vpn_cdb_news_cache_reset()
{
    if(s_url_proc){
        pthread_rwlock_wrlock(&s_url_proc->cache_rwlock);
        dap_http_cache_delete(s_url_proc->cache);
        s_url_proc->cache = NULL;
        pthread_rwlock_unlock(&s_url_proc->cache_rwlock);
    }
}
