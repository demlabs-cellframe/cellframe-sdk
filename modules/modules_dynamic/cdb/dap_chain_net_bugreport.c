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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <zip.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include <json-c/json_object.h>

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "include/dap_enc_ks.h"
#include "dap_enc_key.h"
#include "dap_config.h"
#include "rand/dap_rand.h"
#include "dap_enc.h"

#include "http_status_code.h"
#include "dap_http_simple.h"
#include "dap_enc_http.h"
#include "dap_chain_net_bugreport.h"

#define LOG_TAG "chain_net_bugreport"

#define BUGREPORT_URL "/bugreport"

enum {
    BUGREPORT_STATUS_NOTDEFINED, BUGREPORT_STATUS_NEW, BUGREPORT_STATUS_IN_PROGRESS, BUGREPORT_STATUS_RESOLVED
};

void dap_chain_net_bugreport_add_proc(struct dap_http * sh);
void bugreport_update_statuses(void);

int dap_chain_net_bugreport_init(dap_http_t * a_http)
{
    dap_chain_net_bugreport_add_proc(a_http);
    bugreport_update_statuses();
    return 0;
}

const char *bugreport_get_status_text(int a_status)
{
    switch (a_status) {
    case BUGREPORT_STATUS_NOTDEFINED:
        return "";
        break;
    case BUGREPORT_STATUS_NEW:
        return "new";
        break;
    case BUGREPORT_STATUS_IN_PROGRESS:
        return "in progress";
        break;
    case BUGREPORT_STATUS_RESOLVED:
        return "resolved";
        break;
    }
    return NULL;
}

int bugreport_get_status_by_text(const char *a_status_str)
{
    if(!dap_strcmp(a_status_str, "new"))
        return BUGREPORT_STATUS_NEW;
    else if(!dap_strcmp(a_status_str, "in progress"))
        return BUGREPORT_STATUS_IN_PROGRESS;
    else if(!dap_strcmp(a_status_str, "in progress"))
        return BUGREPORT_STATUS_RESOLVED;
    return BUGREPORT_STATUS_NOTDEFINED;
}

struct json_object *bugreport_get_last_status(char *a_pkeyHash)//, int *a_status_out, char **a_status_date_out)
{
    dap_list_t *l_list_ret = NULL;
    if(!a_pkeyHash || dap_strlen(a_pkeyHash)<1)
        return NULL;
    char *l_dir_str = dap_strdup_printf("%s/var/bugreport", g_sys_dir_path);
    DIR * l_dir = opendir(l_dir_str);
    if(l_dir) {
        struct dirent * l_dir_entry;
        while((l_dir_entry = readdir(l_dir)) != NULL ) {

            const char *l_ext = dap_path_get_ext(l_dir_entry->d_name);
            if(dap_strcmp(l_ext, "status"))
                continue;
            // read status file
            char *l_status_content = NULL;
            size_t l_status_content_len = 0;
            char * l_full_path_status = dap_strdup_printf("%s/%s", l_dir_str, l_dir_entry->d_name);
            if(dap_file_get_contents(l_full_path_status, &l_status_content, &l_status_content_len)) {
                struct json_object *l_jobj = json_tokener_parse((char*) l_status_content);
                DAP_DELETE(l_status_content);
                // if file in json format
                if(l_jobj) {
                    struct json_object *l_obj_pkeyHash = json_object_object_get(l_jobj, "pkeyHash");
                    const char *l_str_hash = json_object_get_string(l_obj_pkeyHash);
                    // search file with pkeyHash = a_pkeyHash
                    if(l_str_hash && !dap_strcmp(l_str_hash, a_pkeyHash)) {
                        // get status from status file
                        struct json_object *l_obj_status = json_object_object_get(l_jobj, "status");
                        if(l_obj_status && json_object_get_type(l_obj_status) == json_type_array) {
                            size_t l_num = json_object_array_length(l_obj_status);
                            struct json_object *l_obj_last_status = l_num > 0 ? json_object_array_get_idx(l_obj_status, l_num - 1) : NULL;
                            // form one item to return
                            {
                                // get bugreport id from filemane
                                size_t l_shift_id = dap_strlen(l_dir_str) + 1 + 18;
                                l_full_path_status[l_shift_id + 5] = '\0';
                                json_object_object_add(l_obj_last_status, "id", json_object_new_string(l_full_path_status + l_shift_id));
                            }

                            // add item to return
                            struct json_object *l_obj_last_status_copy;
                            char* json_str = dap_strdup(json_object_to_json_string(l_obj_last_status));
                            l_list_ret = dap_list_append(l_list_ret, json_str);

                            //json_object_deep_copy(l_obj_last_status, &l_obj_last_status_copy, NULL);
                            //json_object_array_add(l_obj_ret, l_obj_last_status);
                            /*
                            struct json_object *l_obj_last_status_text = l_obj_last_status ? json_object_object_get(l_obj_last_status, "status") : NULL;
                            const char *l_str_status_text = json_object_get_string(l_obj_last_status_text);
                            if(l_str_status_text && dap_strlen(l_str_status_text > 0)) {
                                // status
                                if(a_status_out)
                                    *a_status_out = dap_strdup(l_str_status_text);
                                // date
                                if(a_status_date_out){
                                    struct json_object *l_obj_last_date_text = l_obj_last_status ? json_object_object_get(l_obj_last_status, "date") : NULL;
                                    *a_status_date_out = dap_strdup(json_object_get_string(l_obj_last_status_text));
                                }
                                // return = OK
                                l_ret = 0;
                            }
                            else
                                l_ret = -2;*/
                        }
                        //break;// if only one item return
                    }
                    // free
                    json_object_put(l_jobj);
                }
            }
            DAP_DELETE(l_full_path_status);
        }
        closedir(l_dir);
    }
    DAP_DELETE(l_dir_str);
    if(l_list_ret) {
        struct json_object *l_obj_ret = json_object_new_array();
        dap_list_t *l_list = l_list_ret;
        // create output array
        while(l_list){
            struct json_object *l_jobj = json_tokener_parse((char*) l_list->data);
            json_object_array_add(l_obj_ret, l_jobj);
            l_list = dap_list_next(l_list);
        }
        dap_list_free_full(l_list_ret, free);
        return l_obj_ret;
    }
    return NULL ;
}

int bugreport_add_status(const char *a_filename_bugreport, const char *a_filename_status, const char *a_pkeyHash, int a_status)
{
    time_t l_status_date_time;
    char *l_status_content = NULL;
    size_t l_status_content_len = 0;
    // if the status file exist, then the status time is current, otherwise = time of create bugreport
    if(dap_file_test(a_filename_status)) {
        l_status_date_time = time(NULL);
        dap_file_get_contents(a_filename_status, &l_status_content, &l_status_content_len);
    }
    else {
        struct stat st;
        if(!stat(a_filename_bugreport, &st)) {
            l_status_date_time = st.st_mtim.tv_sec;
        }
        else
            l_status_date_time = time(NULL);
    }
    struct json_object *l_jobj = json_object_new_object();
    // get exist json
    if (l_status_content && l_status_content_len>0){
        l_jobj = json_tokener_parse((char*)l_status_content);
    }
    DAP_DELETE(l_status_content);
    if(!l_jobj)
        l_jobj = json_object_new_object();
    // find exist records
    struct json_object *l_obj_pkey_hash = json_object_object_get(l_jobj, "pkeyHash");
    struct json_object *l_obj_status = json_object_object_get(l_jobj, "status");

/*    { "pkeyHash": "DKQ58CC6YFBFTTEJ",
        "status": [ { "date": "Thu, 26 Nov 20 14:20:46 +0500", "status": "new" },
                    { "date": "Thu, 26 Nov 20 15:05:12 +0500", "status": "in progress" },
                    { "date": "Thu, 26 Nov 20 16:35:11 +0500", "status": "resolved" } ]
    }*/

    // pkeyHash
    if(a_pkeyHash) {
        const char *l_pkeyHash = l_obj_pkey_hash ? json_object_get_string(l_obj_pkey_hash) : NULL;
        // create or update pkeyHash
        if(!l_pkeyHash || dap_strcmp(l_pkeyHash, a_pkeyHash)) {
            if(l_pkeyHash)
                json_object_object_del(l_jobj, "pkeyHash");
            json_object_object_add(l_jobj, "pkeyHash", json_object_new_string(a_pkeyHash));
        }
    }
    // status
    const char *l_status_str = bugreport_get_status_text(a_status);
    if(l_status_str) {
        char l_datetime_buf[1024];
        dap_time_to_str_rfc822(l_datetime_buf, sizeof(l_datetime_buf), l_status_date_time);
        //char *l_datetime_buf = dap_strdup_printf("%lu", l_status_date_time);

        struct json_object *l_jobj_arr = l_obj_status ? l_obj_status : json_object_new_array();
        struct json_object *l_jobj_item = json_object_new_object();
        // date
        json_object_object_add(l_jobj_item, "date", json_object_new_string(l_datetime_buf));
        //status
        json_object_object_add(l_jobj_item, "status", json_object_new_string(l_status_str));
        json_object_array_add(l_jobj_arr, l_jobj_item);

        if(!l_obj_status)
            json_object_object_add(l_jobj, "status", l_jobj_arr);
        //DAP_DELETE(l_datetime_buf);
    }
    const char* json_str = json_object_to_json_string(l_jobj);
    // write json to file
    if(json_str) {
        FILE *l_file = fopen(a_filename_status, "wb");
        if(l_file)
        {

            fwrite(json_str, 1, dap_strlen(json_str), l_file);
            fwrite("\n", 1, 1, l_file);
            fclose(l_file);

        }
    }
    json_object_put(l_obj_pkey_hash);
    json_object_put(l_jobj);
    return 0;
}

void bugreport_update_statuses(void)
{
    char *l_dir_str = dap_strdup_printf("%s/var/bugreport", g_sys_dir_path);
    DIR * l_dir = opendir(l_dir_str);
    if(l_dir) {
        struct dirent * l_dir_entry;
        uint16_t l_acl_idx = 0;
        while((l_dir_entry = readdir(l_dir)) != NULL) {
            if(l_dir_entry->d_name[0] == '\0' || l_dir_entry->d_name[0] == '.')
                continue;
            // don't search in directories
            char * l_full_path = dap_strdup_printf("%s/%s", l_dir_str, l_dir_entry->d_name);
            if(dap_dir_test(l_full_path)) {
                DAP_DELETE(l_full_path);
                continue;
            }
            // read zip file
            zip_stat_t l_sb;
            zip_stat_init(&l_sb);
            // open only archives
            struct zip *l_za;
            int err;
            if((l_za = zip_open(l_full_path, 0, &err)) == NULL) {
                DAP_DELETE(l_full_path);
                continue;
            }
            // check the status file for exists
            char * l_full_path_status = dap_strdup_printf("%s/%s.status", l_dir_str, l_dir_entry->d_name);
            /*if(dap_file_test(l_full_path_status)){
                zip_close(l_za);
                DAP_DELETE(l_full_path);
                DAP_DELETE(l_full_path_status);
                continue;
            }*/
            zip_int64_t i;
            for(i = 0; i < zip_get_num_entries(l_za, 0); i++) {
                if(zip_stat_index(l_za, i, 0, &l_sb) == 0) {
                    int l_data_txt = -1, l_data_json = -1;
                    if((l_data_txt = dap_strcmp(l_sb.name, "data.txt")) == 0 ||
                       (l_data_json = dap_strcmp(l_sb.name, "data.json")) == 0) {
                        // read data.txt file from archive
                        struct zip_file *l_zf = zip_fopen_index(l_za, i, 0);
                        if(!l_zf)
                            break;
                        zip_int64_t l_buf_cur_pos = 0;
                        char *l_buf = DAP_NEW_SIZE(char, l_sb.size + 1);
                        l_buf[l_sb.size]='\0';
                        while(l_buf_cur_pos != l_sb.size) {
                            zip_int64_t len = zip_fread(l_zf, l_buf + l_buf_cur_pos, l_sb.size);
                            if(len < 0) {
                                break;
                            }
                            l_buf_cur_pos += len;
                        }
                        zip_fclose(l_zf);
                        // if data file was read successfully
                        if(l_buf_cur_pos == l_sb.size) {
                            const char *pkeyHash = NULL;
                            struct json_object *l_jobj = NULL;
                            // found pkeyHash from data.txt file
                            if(!l_data_txt) {
                                char *l_end_of_str = dap_strstr_len(l_buf, l_buf_cur_pos, "\n");
                                if(l_end_of_str) {
                                    l_end_of_str[0] = '\0';
                                    pkeyHash = l_buf;
                                }
                            }
                            // found pkeyHash from data.json file
                            else if(!l_data_json) {
                                l_jobj = json_tokener_parse(l_buf);
                                struct json_object *l_obj_pkey_hash = l_jobj ? json_object_object_get(l_jobj, "pKeyHash") : NULL;
                                pkeyHash = l_obj_pkey_hash ? json_object_get_string(l_obj_pkey_hash) : NULL;
                            }
                            // write status file with pkeyHash
                            if(pkeyHash) {
                                bugreport_add_status(l_full_path, l_full_path_status, pkeyHash, BUGREPORT_STATUS_NEW);
                            }
                            json_object_put(l_jobj);
                        }
                        DAP_DELETE(l_buf);
                    }

                }
            }
            DAP_DELETE(l_full_path);
            zip_close(l_za);
        }
        closedir(l_dir);
    }
    DAP_DELETE(l_dir_str);
}

static int64_t bugreport_write_to_file(byte_t *a_request_byte, size_t a_request_size)
{
    int64_t l_report_number = -2;
    if(!a_request_byte || !a_request_size)
        return -1;
    char *l_dir_str = dap_strdup_printf("%s/var/bugreport", g_sys_dir_path);
    dap_mkdir_with_parents(l_dir_str);

    const time_t l_timer = time(NULL);
    struct tm l_tm;
    localtime_r(&l_timer, &l_tm);
    // create unique number for bugreport
    randombytes(&l_report_number, sizeof(int64_t));
    if(l_report_number < 0)
        l_report_number = -l_report_number;
    //l_report_number 5 characters long
    l_report_number %= 100000ll;
    /*
    // l_report_number 20 characters long
    l_report_number -= l_report_number%1000000000000ll;
    l_report_number+=(int64_t)(l_tm.tm_year - 100)*10000000000;
    l_report_number+=(int64_t)(l_tm.tm_mon)*100000000;
    l_report_number+=(int64_t)(l_tm.tm_mday)*1000000;
    l_report_number+=(int64_t)(l_tm.tm_hour)*10000;
    l_report_number+=(int64_t)(l_tm.tm_min)*100;
    l_report_number+=(int64_t)(l_tm.tm_sec);
    */
    char *l_filename_str = dap_strdup_printf("%s/%02d-%02d-%02d_%02d:%02d:%02d_%05lld.brt", l_dir_str,
            l_tm.tm_year - 100, l_tm.tm_mon + 1, l_tm.tm_mday,
            l_tm.tm_hour, l_tm.tm_min, l_tm.tm_sec,
            l_report_number);
    FILE *l_fp;
    if((l_fp = fopen(l_filename_str, "wb")) != NULL) {
        if(fwrite(a_request_byte, 1, a_request_size, l_fp) != a_request_size)
            l_report_number = -3;
        fclose(l_fp);
    }
    DAP_DELETE(l_filename_str);
    DAP_DELETE(l_dir_str);
    return l_report_number;
}


static char* parse_query_string(const char *a_query_str, const char *a_str)
{
    if(!a_query_str)
        return NULL;
    char **l_items = dap_strsplit(a_query_str, "&", -1);
    for(int l_i = 0; l_items[l_i] != NULL ; l_i++) {
        char **l_value = dap_strsplit(l_items[l_i], "=", 2);
        if(dap_str_countv(l_value) == 2) {
            if(!dap_strcmp(a_str, l_value[0])) {
                char *l_ret_str = dap_strdup(l_value[1]);
                dap_strfreev(l_value);
                dap_strfreev(l_items);
                return l_ret_str;
            }
        }
        dap_strfreev(l_value);
    }
    dap_strfreev(l_items);
    return NULL;
}


/**
 * @brief bugreport_http_proc
 * @param a_http_simple
 * @param a_arg
 */
static void bugreport_http_proc(struct dap_http_simple *a_http_simple, void * a_arg)
{
    // data:text/html,<form action=http://192.168.100.92:8079/bugreport/ method=post><input name=a></form>
    // data:text/html,<form action=http://cdb.klvn.io/bugreport/ method=post><input name=a></form>
    log_it(L_DEBUG, "bugreport_http_proc request");
    http_status_code_t * return_code = (http_status_code_t*) a_arg;
    //if(dap_strcmp(cl_st->http->url_path, BUGREPORT_URL) == 0 )
    if(dap_strcmp(a_http_simple->http_client->action, "GET") == 0) {

        /*dap_enc_key_t *l_key = dap_enc_ks_find_http(a_http_simple->http_client);
        char *l_out_str[1024];
        size_t test_len = dap_enc_code(l_key, "gsdg=323&pkeyhash=0xffdsg", strlen("gsdg=323&pkeyhash=0xffdsg"), l_out_str,
                            sizeof(l_out_str), DAP_ENC_DATA_TYPE_B64_URLSAFE);
        uint8_t *in_query_string = NULL;
        size_t in_query_string_size = 0;
        // decode bugreport
        if(l_key) {
            in_query_string_size = dap_strlen(a_http_simple->http_client->in_query_string) + 16;
            in_query_string = DAP_NEW_Z_SIZE(uint8_t, in_query_string_size);
            size_t l_size = dap_enc_decode(l_key, a_http_simple->http_client->in_query_string, a_http_simple->request_size, in_query_string,
                    in_query_string_size, DAP_ENC_DATA_TYPE_B64_URLSAFE);
        }*/


        size_t l_url_len = dap_strlen(a_http_simple->http_client->url_path);
        if(!l_url_len) {
                    a_http_simple->reply = dap_strdup_printf("Unique Bug Report number required)");
                    *return_code = Http_Status_NotFound;
                }
        else{
            char *pkeyhash = parse_query_string(a_http_simple->http_client->in_query_string, "pkeyhash");
            if(!pkeyhash){
                a_http_simple->reply = dap_strdup("[{ \"error\": \"pkeyhash not found in request\"}]");
            }
            else{
                struct json_object *l_jobj= bugreport_get_last_status(pkeyhash);//"DKQ58CC6YFBFTTEJ");//"0x845AC58041A72C25F40ACBBF54F2A93BABB91EB668ABE1F7B5750CD2DD26A666");//
                const char* json_str = json_object_to_json_string(l_jobj);
                a_http_simple->reply = dap_strdup(json_str);
                // free
                json_object_put(l_jobj);
                DAP_DELETE(pkeyhash);
            }

            *return_code = Http_Status_OK;
        }

        a_http_simple->reply_size = strlen(a_http_simple->reply);
    }
    else if(dap_strcmp(a_http_simple->http_client->action, "POST") == 0) {
        //a_http_simple->request_byte;
        //a_http_simple->request_size;
        //a_http_simple->http->in_content_length;

        dap_enc_key_t *l_key = dap_enc_ks_find_http(a_http_simple->http_client);
        uint8_t *l_request_byte = NULL;
        size_t l_request_size = 0;
        // decode bugreport
        if(l_key) {
            l_request_size = a_http_simple->request_size + 16;
            l_request_byte = DAP_NEW_Z_SIZE(uint8_t, l_request_size);
            l_request_size = dap_enc_decode(l_key, a_http_simple->request, a_http_simple->request_size, l_request_byte,
                    l_request_size, DAP_ENC_DATA_TYPE_RAW);
        }
        else {
            // key not found -> save without decoding
            l_request_byte = a_http_simple->request_byte;
            l_request_size = a_http_simple->request_size;
        }
        int64_t l_bugreport_number = bugreport_write_to_file(l_request_byte, l_request_size); //a_http_simple->request_byte, a_http_simple->request_size);
        if(l_key) {
            DAP_DELETE(l_request_byte);
        }
        if(l_bugreport_number >= 0) {
            //l_report_number 5 characters long
            a_http_simple->reply = dap_strdup_printf("Bug Report #%05lld saved successfully)", l_bugreport_number);
            //l_report_number 20 characters long
            //a_http_simple->reply = dap_strdup_printf("Bug Report #%020lld saved successfully)", l_bugreport_number);
        }
        else {
            a_http_simple->reply = dap_strdup_printf("Bug Report not saved( code=%lld", l_bugreport_number);
        }
        a_http_simple->reply_size = strlen(a_http_simple->reply);
        *return_code = Http_Status_OK;

    } else {
        log_it(L_ERROR, "Wrong action '%s' for the request. Must be 'POST' or 'GET'", a_http_simple->http_client->action);
        a_http_simple->reply = dap_strdup_printf("[{ \"error\": \"Wrong action '%s' for the request. Must be 'POST' or 'GET'\"}]",
                a_http_simple->http_client->action);
        a_http_simple->reply_size = strlen(a_http_simple->reply);
        *return_code = Http_Status_OK;
    }
    strcpy(a_http_simple->reply_mime, "application/json");
}

/**
 * @brief dap_chain_net_bugreport_add_proc
 * @param sh HTTP server instance
 */
void dap_chain_net_bugreport_add_proc(struct dap_http * sh)
{
    const char * url = BUGREPORT_URL;
    dap_http_simple_proc_add(sh, url, 14096, bugreport_http_proc);
}

