/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <rand/dap_rand.h>

#include <time.h>

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_client_remote.h"

#include "dap_http.h"
#include "dap_http_client.h"
#include "dap_http_simple.h"

#include "dap_enc.h"
#include "dap_enc_key.h"
#include "dap_enc_ks.h"
#include "dap_enc_http.h"
#include "dap_enc_base64.h"
#include "dap_server.h"

#include "dap_chain_node_cli.h"
#include "dap_chain_global_db.h"

#include "http_status_code.h"

#include "dap_chain_net_srv_vpn_cdb.h"
#include "dap_chain_net_srv_vpn_cdb_auth.h"

#define LOG_TAG "dap_chain_net_srv_vpn_cdb_auth"

#define OP_CODE_LOGIN_INCORRECT_PSWD "0xf2"
#define OP_CODE_LOGIN_INCORRECT_SIGN "0xf2"
#define OP_CODE_NOT_FOUND_LOGIN_IN_DB "0xf3"
#define OP_CODE_SUBSCRIBE_EXPIRIED "0xf4"
#define OP_CODE_INCORRECT_SYMOLS "0xf6"
#define OP_CODE_LOGIN_INACTIVE  "0xf7"
#define OP_CODE_SERIAL_ACTIVED  "0xf8"


dap_enc_http_callback_t s_callback_success = NULL;

static char * s_domain = NULL;
static char * s_group_users = NULL;
static char * s_group_serials = NULL;
static char * s_group_serials_activated = NULL;

static char * s_group_password = NULL;
static char * s_group_first_name = NULL;
static char * s_group_last_name = NULL;
static char * s_group_email = NULL;
static char * s_group_ts_updated = NULL;
static char * s_group_ts_last_login = NULL;
static char * s_group_cookies = NULL;
static char * s_group_cookie = NULL;
static char * s_group_ts_active_till = NULL;

static char * s_salt_str = "Ijg24GAS56h3hg7hj245b";

static bool s_is_registration_open = false;
static bool s_mode_passwd = true;

// hook paths
static char *s_hook_user_create = NULL;
static char *s_hook_user_login = NULL;
static char *s_hook_user_update = NULL;
static char *s_hook_user_delete = NULL;

static char *s_hook_serial_generate = NULL;
static char *s_hook_serial_login = NULL;
static char *s_hook_serial_activate = NULL;
static char *s_hook_serial_update = NULL;
static char *s_hook_serial_delete = NULL;
static char *s_hook_serial_deactivate = NULL;

static int s_input_validation(const char * str);
static void s_http_enc_proc(enc_http_delegate_t *a_delegate, void * a_arg);
static void s_http_enc_proc_key(enc_http_delegate_t *a_delegate, void * a_arg);
static void s_http_proc(dap_http_simple_t *a_http_simple, void * arg );

static char *register_hook(const char *a_cfg_name)
{
    char *l_hook_path_ret = NULL;
    const char *l_hook_path = dap_config_get_item_str(g_config, "cdb_auth", a_cfg_name);
    if(dap_file_test(l_hook_path))
        l_hook_path_ret = dap_strdup(l_hook_path);
    else if(l_hook_path) {
        log_it(L_WARNING, "file for %s = %s not found", a_cfg_name, l_hook_path);
    }
    return l_hook_path_ret;
}

static int run_hook(char *a_hook_path, char *a_format, ...)
{
    if(!a_hook_path)
        return -1;
    char *l_params = NULL;
    va_list l_args;
    va_start(l_args, a_hook_path);
    l_params = dap_strdup_vprintf(a_format, l_args);
    va_end(l_args);
    char *l_cmd = dap_strdup_printf("%s %s", a_hook_path, l_params);
    int l_ret = system(l_cmd);
    DAP_DELETE(l_params);
    DAP_DELETE(l_cmd);
    return l_ret;
}

/**
 * @brief dap_chain_net_srv_vpn_cdb_auth_init
 * @param a_domain
 * @return
 */
int dap_chain_net_srv_vpn_cdb_auth_init (const char * a_domain, const char * a_mode, bool a_is_registration_open)
{
    s_is_registration_open = a_is_registration_open;

    s_domain = dap_strdup(a_domain);

    // Prefix for gdb groups
    s_group_users = dap_strdup_printf("cdb.%s.users",s_domain);
    s_group_serials = dap_strdup_printf("cdb.%s.serials",s_domain);
    s_group_serials_activated = dap_strdup_printf("cdb.%s.serials_activated",s_domain);

    // Cookie -> login
    s_group_cookies = dap_strdup_printf("cdb.%s.cookies",s_domain);

    // mode: passwd or serial
    if(!dap_strcmp(a_mode, "serial"))
        s_mode_passwd = false;
    else if(!dap_strcmp(a_mode, "passwd"))
        s_mode_passwd = true;
    else{
        log_it( L_ERROR, "Unknown cdb mode=%s", a_mode);
        return -1;
    }

    // Login -> Password, First Name, Last Name, Email, Cookie,Timestamp Last Update, Timestamp Last Login
    s_group_password = dap_strdup_printf("%s.password",s_group_users);
    s_group_first_name = dap_strdup_printf("%s.first_name",s_group_users);
    s_group_last_name = dap_strdup_printf("%s.last_name",s_group_users);
    s_group_email = dap_strdup_printf("%s.email",s_group_users);
    s_group_cookie  = dap_strdup_printf("%s.cookie",s_group_users);
    s_group_ts_updated = dap_strdup_printf("%s.ts_updated",s_group_users);
    s_group_ts_last_login = dap_strdup_printf("%s.ts_last_login",s_group_users);
    s_group_ts_active_till = dap_strdup_printf("%s.ts_active_till",s_group_users);

    // load hook paths
    s_hook_user_create = register_hook("hook_user_create");
    s_hook_user_login = register_hook("hook_user_login");
    s_hook_user_update = register_hook("hook_user_update");
    s_hook_user_delete = register_hook("hook_user_delete");

    s_hook_serial_generate = register_hook("hook_serial_generate");
    s_hook_serial_login = register_hook("hook_serial_login");
    s_hook_serial_activate = register_hook("hook_serial_activate");
    s_hook_serial_update = register_hook("hook_serial_update");
    s_hook_serial_delete = register_hook("hook_serial_delete");
    s_hook_serial_deactivate = register_hook("hook_serial_deactivate");
    //run_hook(s_hook_serial_update, "serial=%s active_days=%lld", l_serial.header.serial, l_active_days);

}

/**
 * @brief dap_chain_net_srv_vpn_cdb_auth_deinit
 */
void dap_chain_net_srv_vpn_cdb_auth_deinit()
{
}

/**
 * @brief dap_chain_net_srv_vpn_cdb_auth_set_callback
 * @param a_callback_success
 */
void dap_chain_net_srv_vpn_cdb_auth_set_callback(dap_enc_http_callback_t a_callback_success)
{
    s_callback_success = a_callback_success;
}

/*
 * Convert XXXXXXXXXXXXXXXX -> XXXX-XXXX-XXXX-XXXX
 */
static char* make_fullserial(const char * a_serial)
{
    if(dap_strlen(a_serial)!=16)
        return dap_strdup(a_serial);
    return dap_strdup_printf("%c%c%c%c-%c%c%c%c-%c%c%c%c-%c%c%c%c",
            a_serial[0], a_serial[1], a_serial[2], a_serial[3],
            a_serial[4], a_serial[5], a_serial[6], a_serial[7],
            a_serial[8], a_serial[9], a_serial[10], a_serial[11],
            a_serial[12], a_serial[13], a_serial[14], a_serial[15]
            );
}

/**
 * @brief dap_chain_net_srv_vpn_cdb_auth_check_password
 * @param a_login
 * @param a_password
 * @return
 */
int dap_chain_net_srv_vpn_cdb_auth_check_login(const char * a_login, const char * a_password)
{
    int l_ret;

    size_t l_tmp_size=0;
    dap_chain_hash_fast_t *l_gdb_password_hash;
    if ( (l_gdb_password_hash = (dap_chain_hash_fast_t*) dap_chain_global_db_gr_get (
             a_login,&l_tmp_size  ,s_group_password ) ) ==NULL ){
        // No user in database
        return -1;
    }

    char * l_hash_str = dap_strdup_printf("%s%s",a_password, s_salt_str );
    dap_chain_hash_fast_t l_password_hash = {0};
    dap_hash_fast(l_hash_str,dap_strlen(l_hash_str), &l_password_hash );
    DAP_DELETE(l_hash_str);

    l_ret = (memcmp(&l_password_hash, l_gdb_password_hash,sizeof (l_password_hash) ) == 0)? 0: -2;
    DAP_DELETE(l_gdb_password_hash);

    // if password check passed lets see is it active or not
    if ( l_ret == 0){
        time_t *l_ts_active_till= (time_t*) dap_chain_global_db_gr_get( a_login, &l_tmp_size, s_group_ts_active_till );
        if ( l_ts_active_till ){
            if ( *l_ts_active_till < time(NULL) )
                l_ret = -4;
        }else
            l_ret = -3;
    }
    return l_ret;
}

/**
 * @brief dap_chain_net_srv_vpn_cdb_auth_activate_serial
 * @param a_login
 * @param a_password
 * @return
 */
int dap_chain_net_srv_vpn_cdb_auth_activate_serial(const char * a_serial_raw, const char * a_serial, const char * a_sign, const char * a_pkey)
{
    int l_ret = -1;
    if(!a_sign || !a_pkey)
        return -2;//OP_CODE_LOGIN_INCORRECT_SIGN
    dap_serial_key_t *l_serial_key = dap_chain_net_srv_vpn_cdb_auth_get_serial_param(a_serial, NULL);
    // not found
    if(!l_serial_key)
        return -1;//OP_CODE_NOT_FOUND_LOGIN_IN_DB
    // already activated
    if(l_serial_key->header.activated) {
        l_ret = 0;// OK
    }
    else {
        // check sign
        int l_res = 0;
        byte_t *l_pkey_raw = NULL;
        size_t l_pkey_raw_size = 0;
        dap_enc_key_type_t l_key_type;
        {
            // verify sign
            byte_t *l_sign_raw = NULL;
            size_t l_sign_length = dap_strlen(a_sign);
            l_sign_raw = DAP_NEW_Z_SIZE(byte_t, l_sign_length * 2);
            size_t l_sign_raw_size = dap_enc_base64_decode(a_sign, l_sign_length, l_sign_raw, DAP_ENC_DATA_TYPE_B64_URLSAFE);
            dap_sign_t *l_sign = (dap_sign_t*) l_sign_raw; //dap_sign_pack(l_client_key, l_sign_raw, l_sign_raw_size, l_pkey_raw, l_pkey_length);
            //get key type for pkey
            dap_sign_type_t l_chain_sign_type;
            l_chain_sign_type.raw = l_sign_raw_size > 0 ? l_sign->header.type.raw : SIG_TYPE_NULL;
            l_key_type =  dap_sign_type_to_key_type(l_chain_sign_type);
            size_t l_serial_len = dap_strlen(a_serial_raw);
            l_res = dap_sign_verify(l_sign, a_serial_raw, l_serial_len);
            if(!l_res){
                DAP_DELETE(l_sign_raw);
                return -2;//OP_CODE_LOGIN_INCORRECT_SIGN
            }

            // deserialize pkey
            dap_enc_key_t *l_client_key = NULL;
            size_t l_pkey_length = dap_strlen(a_pkey);
            l_pkey_raw = DAP_NEW_Z_SIZE(byte_t, l_pkey_length);
            memset(l_pkey_raw, 0, l_pkey_length);
            l_pkey_raw_size = dap_enc_base64_decode(a_pkey, l_pkey_length, l_pkey_raw, DAP_ENC_DATA_TYPE_B64_URLSAFE);
            l_client_key = dap_enc_key_new(l_key_type); //DAP_ENC_KEY_TYPE_SIG_TESLA
            l_res = dap_enc_key_deserealize_pub_key(l_client_key, l_pkey_raw, l_pkey_raw_size);
            // pkey from sign
            size_t l_pkey_sign_size = 0;
            uint8_t *l_pkey_sign = dap_sign_get_pkey(l_sign, &l_pkey_sign_size);
            // activate serial key
            if(l_pkey_sign_size == l_pkey_raw_size && !memcmp(l_pkey_sign, l_pkey_raw, l_pkey_sign_size)) {
                // added pkey to serial
                l_serial_key->header.ext_size = l_pkey_raw_size;
                l_serial_key = DAP_REALLOC(l_serial_key, dap_serial_key_len(l_serial_key));
                l_serial_key->header.activated = time(NULL);
                if(l_serial_key->header.expired)
                    l_serial_key->header.expired = l_serial_key->header.activated + l_serial_key->header.expired;
                l_serial_key->header.pkey_type = l_key_type;
                memcpy(l_serial_key->ext, l_pkey_raw, l_pkey_raw_size);
                // save updated serial
                if(dap_chain_global_db_gr_set(dap_strdup(l_serial_key->header.serial), l_serial_key,
                        dap_serial_key_len(l_serial_key),
                        s_group_serials_activated)) {
                    dap_chain_global_db_gr_del(l_serial_key->header.serial, s_group_serials);
                    l_ret = 0; // OK
                }
            }
            // bad pkey
            else
                l_ret = -2;//OP_CODE_LOGIN_INCORRECT_SIGN
            DAP_DELETE(l_sign_raw);
        }
        DAP_DELETE(l_pkey_raw);
    }
    DAP_DELETE(l_serial_key);
    return l_ret;
}

/**
 * @brief dap_chain_net_srv_vpn_cdb_auth_check_password
 * @param a_login
 * @param a_password
 * @return
 */
int dap_chain_net_srv_vpn_cdb_auth_check_serial(const char * a_serial, const char * a_pkey_b64)
{
    int l_ret = 0;
    dap_serial_key_t *l_serial_key = dap_chain_net_srv_vpn_cdb_auth_get_serial_param(a_serial, NULL);
    // not found
    if(!l_serial_key)
        return -1;
    // inactive serial key
    if(!l_serial_key->header.activated) {
        l_ret = -3;
    }
    // check time expired
    else if(l_serial_key->header.expired) {
        if((l_serial_key->header.activated + l_serial_key->header.expired) < time(NULL))
            l_ret = -4;
    }
    else {
        // check pkey
        dap_enc_key_t *l_client_key = NULL;
        size_t l_pkey_length = dap_strlen(a_pkey_b64);
        byte_t *l_pkey_raw = DAP_NEW_Z_SIZE(byte_t, l_pkey_length);
        memset(l_pkey_raw, 0, l_pkey_length);
        size_t l_pkey_raw_size = dap_enc_base64_decode(a_pkey_b64, l_pkey_length, l_pkey_raw,
                DAP_ENC_DATA_TYPE_B64_URLSAFE);
        // pkey from sign
        size_t l_pkey_sign_size = l_serial_key->header.ext_size;
        uint8_t *l_pkey_sign = l_serial_key->ext;
        // compare pkeys
        if(l_pkey_sign_size != l_pkey_raw_size || memcmp(l_pkey_sign, l_pkey_raw, l_pkey_sign_size)) {
            l_ret = -2;
        }
        DAP_DELETE(l_pkey_raw);
    }
    return l_ret;
}

/**
 * @brief s_input_validation
 * @param str
 * @return
 */
static int s_input_validation(const char * str)
{
        // The compiler will stack "multiple" "strings" "end" "to" "end"
        // into "multiplestringsendtoend", so we don't need one giant line.
        static const char *nospecial="0123456789"
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                ".=@?_!#$%-";// /+
        while(*str) // Loop until (*url) == 0.  (*url) is about equivalent to url[0].
        {
                // Can we find the character at *url in the string 'nospecial'?
                // If not, it's a special character and we should return 0.
                if(strchr(nospecial, *str) == NULL){
                    return(0);
                }
                str++; // Jump to the next character.  Adding one to a pointer moves it ahead one element.
        }

        return(1); // Return 1 for success.
}

/**
 * Generate serial number like xxx-xxx-xxx
 * without symbols 0,1,L,I,O
 * a_group_sepa may be NULL
 */
static char* generate_serial(int a_group_count, int a_group_len, const char *a_group_sepa)
{
    size_t l_group_sepa_len = a_group_sepa ? strlen(a_group_sepa) : 0;
    char *l_serial = DAP_NEW_Z_SIZE(char, a_group_count * (a_group_len + l_group_sepa_len));
    int l_serial_pos = 0;
    for(int l_group_count = 0; l_group_count < a_group_count; l_group_count++) {
        for(int l_group_len = 0; l_group_len < a_group_len; l_group_len++) {
            uint32_t l_max_len = 'Z' - 'A' + 5; //['Z' - 'A' - 3]alpha + [10 - 2]digit
            uint32_t l_value = random_uint32_t(l_max_len);
            char l_sym;
            if(l_value < 8)
                l_sym = '2' + l_value;
            // replace unused characters I,O,L
            else if(l_value == 'I' - 'A' + 8)
                l_sym = 'X';
            else if(l_value == 'L' - 'A' + 8)
                l_sym = 'Y';
            else if(l_value == 'O' - 'A' + 8)
                l_sym = 'Z';
            else
                l_sym = 'A' + l_value - 8;
            l_serial[l_serial_pos] = l_sym;
            l_serial_pos++;
        }
        // copy separator to serial
        if(l_group_sepa_len && l_group_count < a_group_count - 1) {
            dap_stpcpy(l_serial + l_serial_pos, a_group_sepa);
            l_serial_pos += l_group_sepa_len;
        }
    }
    return l_serial;
}


size_t dap_serial_key_len(dap_serial_key_t *a_serial_key)
{
    if(!a_serial_key)
        return 0;
    return sizeof(dap_serial_key_t) + a_serial_key->header.ext_size;
}

/**
 * @brief dap_chain_net_srv_vpn_cdb_auth_cli_cmd_serial
 * @param a_user_str
 * @param a_arg_index
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @param a_group_out
 * @return
 */
dap_serial_key_t* dap_chain_net_srv_vpn_cdb_auth_get_serial_param(const char *a_serial_str, const char **a_group_out)
{
    const char *l_group_out = s_group_serials_activated;
    if(!a_serial_str)
        return NULL;
    size_t l_serial_data_len = 0;
    dap_serial_key_t *l_serial_key = (dap_serial_key_t*)dap_chain_global_db_gr_get(a_serial_str, &l_serial_data_len, s_group_serials_activated);
    if(!l_serial_key){
        l_serial_key = (dap_serial_key_t*)dap_chain_global_db_gr_get(a_serial_str, &l_serial_data_len, s_group_serials);
        l_group_out = s_group_serials;
    }
    if(l_serial_data_len>=sizeof(dap_serial_key_t)){
        if(a_group_out)
            *a_group_out = l_group_out;
        return l_serial_key;
    }
    DAP_DELETE(l_serial_key);
    return NULL;
}

/**
 * @brief dap_chain_net_srv_vpn_cdb_auth_cli_cmd_serial
 * @param a_user_str
 * @param a_arg_index
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return
 */
int dap_chain_net_srv_vpn_cdb_auth_cli_cmd_serial(const char *a_serial_str, int a_arg_index, int a_argc, char ** a_argv, char **a_str_reply)
{
    int l_ret = 0;
    // Command 'serial list'
    if(!dap_strcmp(a_serial_str, "list")) {
        const char * l_serial_count_str = NULL;
        const char * l_serial_shift_str = NULL;
        int l_serial_nototal = dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-nototal", NULL);
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-n", &l_serial_count_str);
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-shift", &l_serial_shift_str);
        size_t l_serial_count = l_serial_count_str ? strtoll(l_serial_count_str, NULL, 10) : 0;
        size_t l_serial_shift = l_serial_shift_str ? strtoll(l_serial_shift_str, NULL, 10)+1 : 1;
        size_t l_total = dap_chain_global_db_driver_count(s_group_serials, l_serial_shift);
        l_serial_count = l_serial_count ? min(l_serial_count, l_total - l_serial_shift) : l_total;
        dap_store_obj_t *l_obj = dap_chain_global_db_driver_cond_read(s_group_serials, l_serial_shift, &l_serial_count);
        if(l_serial_count > 0) {
            dap_string_t *l_keys = l_serial_count > 1 ? dap_string_new("serial keys:\n") : dap_string_new("serial key: ");
            for(size_t i = 0; i < l_serial_count; i++) {
                if((l_obj + i)->value_len < sizeof(dap_serial_key_t))
                    continue;
                dap_serial_key_t *l_serial = (dap_serial_key_t*) (l_obj + i)->value;
                dap_string_append(l_keys, l_serial->header.serial);
                //if(i < l_serial_count - 1)
                    dap_string_append(l_keys, "\n");
            }
            if(!l_serial_nototal){
                char *l_total_str = dap_strdup_printf("total %u keys", l_total);
                dap_string_append(l_keys, l_total_str);
                DAP_DELETE(l_total_str);
                //dap_chain_node_cli_set_reply_text(a_str_reply, "\ntotal %u keys", l_total);
                //return 0;
            }
            dap_chain_node_cli_set_reply_text(a_str_reply, "%s", l_keys->str);
            dap_string_free(l_keys, true);
            dap_store_obj_free(l_obj, l_serial_count);
        }
        else
            dap_chain_node_cli_set_reply_text(a_str_reply, "keys not found");
        return 0;
    }
    else
    // Command 'serial generate'
    if(!dap_strcmp(a_serial_str, "generate")) {
        const char * l_serial_count_str = NULL;
        const char * l_active_days_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-n", &l_serial_count_str);
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-active_days", &l_active_days_str);
        uint32_t l_serial_count = l_serial_count_str ? strtoll(l_serial_count_str, NULL, 10) : 1;
        size_t l_active_days = l_active_days_str ? strtoll(l_active_days_str, NULL, 10) : 0;
        if(l_serial_count < 1)
            l_serial_count = 1;
        dap_string_t *l_keys = l_serial_count > 1 ? dap_string_new("serial keys:\n") : dap_string_new("serial key: ");
        for(uint32_t i = 0; i < l_serial_count; i++) {
            dap_serial_key_t l_serial;
            memset(&l_serial, 0, sizeof(dap_serial_key_t));
            while(1) {
                char *l_serial_str = generate_serial(4, 4, "-");
                uint8_t *l_serial_str_prev = dap_chain_global_db_gr_get(l_serial_str, NULL, s_group_serials);
                if(l_serial_str_prev)
                    DAP_DELETE(l_serial_str_prev);
                else{
                    strncpy(l_serial.header.serial, l_serial_str, sizeof(l_serial.header.serial));
                    if(l_active_days)
                        l_serial.header.expired = l_active_days * 86400;// days to sec
                    break;
                }
            };
            l_serial.header.ext_size = 0;

            if(dap_chain_global_db_gr_set(dap_strdup(l_serial.header.serial), &l_serial, sizeof(l_serial), s_group_serials)) {
                dap_string_append(l_keys, l_serial.header.serial);
                if(i < l_serial_count - 1)
                    dap_string_append(l_keys, "\n");
            }
            run_hook(s_hook_serial_generate, "serial=%s active_days=%lld", l_serial.header.serial, l_active_days);
        }
        dap_chain_node_cli_set_reply_text(a_str_reply, "generated new %s", l_keys->str);
        dap_string_free(l_keys, true);
        // save gdb
        dap_chain_global_db_flush();
        return 0;
    }
    else
    // Command 'serial update'
    if(!dap_strcmp(a_serial_str, "update")) {
        const char * l_serial_number_str = NULL;
        const char * l_active_days_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-serial", &l_serial_number_str);
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-active_days", &l_active_days_str);
        size_t l_active_days = l_active_days_str ? strtoll(l_active_days_str, NULL, 10) : 0;
        if(!l_serial_number_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "option '-serial XXXX-XXXX-XXXX-XXXX' is not defined");
        }
        else if(!l_active_days_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "option '-active_days <active days that left for serial after activation>' is not defined");
        }
        else {
            const char *l_group;
            dap_serial_key_t *l_serial_key = dap_chain_net_srv_vpn_cdb_auth_get_serial_param(l_serial_number_str, &l_group);
            if(l_serial_key){
                l_serial_key->header.expired = l_active_days;
                // save updated serial
                if(dap_chain_global_db_gr_set(dap_strdup(l_serial_key->header.serial), l_serial_key, dap_serial_key_len(l_serial_key), l_group)) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "serial '%s' successfully updated", l_serial_key->header.serial);
                    DAP_DELETE(l_serial_key);
                    // save gdb
                    dap_chain_global_db_flush();
                    run_hook(s_hook_serial_update, "serial=%s active_days=%lld", l_serial_key->header.serial, l_serial_key->header.activated ? "activated" : "inactive", l_active_days);
                    return 0;
                }
                else{
                    dap_chain_node_cli_set_reply_text(a_str_reply, "serial '%s' can't updated", l_serial_key->header.serial);
                }
                DAP_DELETE(l_serial_key);
            }
            else{
                dap_chain_node_cli_set_reply_text(a_str_reply, "serial '%s' not found", l_serial_number_str);
            }
            return 0;
        }
    }
    else
    // Command 'serial info'
    if(!dap_strcmp(a_serial_str, "info")) {
        int l_ret = 0;
        const char * l_serial_number_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-serial", &l_serial_number_str);
        if(!l_serial_number_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "option '-serial XXXX-XXXX-XXXX-XXXX' is not defined");
            l_ret = -1;
        }
        else {
            const char *l_group;
            dap_serial_key_t *l_serial_key = dap_chain_net_srv_vpn_cdb_auth_get_serial_param(l_serial_number_str, &l_group);
            if(l_serial_key) {
                char l_out_str[121];
                char *l_str_message;
                // form full string with serial info
                if(l_serial_key->header.activated) {
                    if(dap_time_to_str_rfc822(l_out_str, 120, l_serial_key->header.activated) > 0) {// instead of strftime
                        // form expired time string
                        char *l_expired_txt = NULL;
                        if(l_serial_key->header.expired) {
                            time_t l_expired_sec = l_serial_key->header.expired - time(NULL);
                            if(l_expired_sec < 0)
                                l_expired_txt = dap_strdup("0 days");
                            else
                                l_expired_txt = dap_strdup_printf("%lld days", l_expired_sec/(24*3600));
                        }
                        else
                            l_expired_txt = dap_strdup("no time limit");
                        l_str_message = dap_strdup_printf("serial %s actitated %s\nexpired: %s", l_serial_key->header.serial, l_out_str, l_expired_txt);
                        DAP_DELETE(l_expired_txt);
                    }
                    else {
                        l_str_message = dap_strdup_printf("serial %s actitated ???", l_serial_key->header.serial);
                        l_ret = -3;
                    }
                }
                // not activated serial
                else {
                    // form expired time string
                    char *l_expired_txt = NULL;
                    if(l_serial_key->header.expired) {
                        l_expired_txt = dap_strdup_printf("%lld days", l_serial_key->header.expired/(24*3600));
                    }
                    else
                        l_expired_txt = dap_strdup("no time limit");
                    l_str_message = dap_strdup_printf("serial %s not actitated\nexpired: %s", l_serial_key->header.serial, l_expired_txt);
                    DAP_DELETE(l_expired_txt);
                }
                dap_chain_node_cli_set_reply_text(a_str_reply, l_str_message);

                DAP_DELETE(l_str_message);
            }
            else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "serial '%s' not found", l_serial_number_str);
                l_ret = -2;
            }

            DAP_DELETE(l_serial_key);
        }
        return l_ret;

    }
    else
    // Command 'serial delete'
    if(!dap_strcmp(a_serial_str, "delete")) {
        int l_ret = 0;
        const char * l_serial_number_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-serial", &l_serial_number_str);
        if(!l_serial_number_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "option '-serial XXXX-XXXX-XXXX-XXXX' is not defined");
            l_ret = -1;
        }
        else {
            const char *l_group;
            dap_serial_key_t *l_serial_key = dap_chain_net_srv_vpn_cdb_auth_get_serial_param(l_serial_number_str, &l_group);
            if(l_serial_key) {
                if(dap_chain_global_db_gr_del(l_serial_key->header.serial, l_group)){
                    dap_chain_node_cli_set_reply_text(a_str_reply, "serial '%s' deleted", l_serial_key->header.serial);
                    run_hook(s_hook_serial_delete, "serial=%s", l_serial_key->header.serial);
                }
                else {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "serial '%s' not deleted", l_serial_key->header.serial);
                    l_ret = -4;
                }
            }
            else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "serial '%s' not found", l_serial_number_str);
                l_ret = -2;
            }

            DAP_DELETE(l_serial_key);
        }
        return l_ret;
    }
    else
    // Command 'serial deactivate'
    if(!dap_strcmp(a_serial_str, "deactivate")) {
        int l_ret = 0;
        const char * l_serial_number_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-serial", &l_serial_number_str);
        if(!l_serial_number_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "option '-serial XXXX-XXXX-XXXX-XXXX' is not defined");
            l_ret = -1;
        }
        else {
            const char *l_group;
            dap_serial_key_t *l_serial_key = dap_chain_net_srv_vpn_cdb_auth_get_serial_param(l_serial_number_str, &l_group);
            if(l_serial_key) {
                if(!l_serial_key->header.activated){
                    dap_chain_node_cli_set_reply_text(a_str_reply, "serial '%s' already deactivated", l_serial_number_str);
                }
                else{
                    if(l_serial_key->header.expired)
                        l_serial_key->header.expired = l_serial_key->header.expired - l_serial_key->header.activated;
                    l_serial_key->header.activated = 0;

                    // pkey in l_serial_key->ext remains
                    // save updated serial
                    if(dap_chain_global_db_gr_set(dap_strdup(l_serial_key->header.serial), l_serial_key, dap_serial_key_len(l_serial_key), s_group_serials)) {
                        dap_chain_global_db_gr_del(l_serial_key->header.serial, s_group_serials_activated);
                        run_hook(s_hook_serial_deactivate, "serial=%s", l_serial_key->header.serial);
                        l_ret = 0; // OK
                    }
                    else
                        l_ret = -5;
                }
            }
            else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "serial '%s' not found", l_serial_number_str);
                l_ret = -2;
            }

            DAP_DELETE(l_serial_key);
        }
        return l_ret;
    }
    else {
        dap_chain_node_cli_set_reply_text(a_str_reply, "unknown subcommand %s, use 'generate', 'list' or 'update'", a_serial_str);
    }
    return -1;
}

/**
 * @brief dap_chain_net_srv_vpn_cdb_auth_cli_cmd_user
 * @param a_user_str
 * @param a_arg_index
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return
 */
int dap_chain_net_srv_vpn_cdb_auth_cli_cmd_user(const char *a_user_str, int a_arg_index, int a_argc, char ** a_argv, char **a_str_reply)
{
    int l_ret = 0;
    dap_string_t * l_ret_str = dap_string_new("");
    // Command 'user create'
    bool l_is_user_create = (dap_strcmp(a_user_str, "create") == 0 );
    bool l_is_user_update = (dap_strcmp(a_user_str, "update") == 0 );
    if ( l_is_user_create  || l_is_user_update ){
        const char * l_login_str = NULL;
        const char * l_password_str = NULL;
        const char * l_first_name_str = NULL;
        const char * l_last_name_str = NULL;
        const char * l_email_str = NULL;
        const char * l_active_days_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "--login", &l_login_str);
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "--password", &l_password_str);
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "--first_name", &l_first_name_str);
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "--last_name", &l_last_name_str);
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "--email", &l_email_str);
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "--active_days", &l_active_days_str);

        if ( ( l_is_user_create && l_login_str && l_password_str ) ||
             ( l_is_user_update && l_login_str && ( l_password_str || l_first_name_str || l_last_name_str || l_email_str ) ) ){

            if (l_password_str){
                char * l_hash_str = dap_strdup_printf("%s%s",l_password_str, s_salt_str );
                dap_chain_hash_fast_t *l_password_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
                dap_hash_fast(l_hash_str,dap_strlen(l_hash_str), l_password_hash );
                DAP_DELETE(l_hash_str);
                dap_chain_global_db_gr_set(dap_strdup(l_login_str), l_password_hash,sizeof(*l_password_hash),s_group_password );
            }

            if ( l_first_name_str )
                dap_chain_global_db_gr_set(dap_strdup(l_login_str), dap_strdup(l_first_name_str),strlen(l_first_name_str)+1,s_group_first_name );

            if ( l_last_name_str )
                dap_chain_global_db_gr_set(dap_strdup(l_login_str), dap_strdup(l_last_name_str),strlen(l_last_name_str)+1,s_group_last_name );

            if ( l_email_str )
                dap_chain_global_db_gr_set(dap_strdup(l_login_str), dap_strdup(l_email_str),strlen(l_email_str)+1,s_group_email );

            // Update timestamp
            dap_chain_time_t *l_time = DAP_NEW_Z(dap_chain_time_t);
            *l_time = dap_chain_time_now();
            dap_chain_global_db_gr_set(dap_strdup(l_login_str), l_time,sizeof (*l_time),s_group_ts_updated );
            l_time = NULL; // to prevent usage uleased memory that could be free in any moment

            uint64_t l_active_days = 0;
            if ( l_active_days_str ){
                l_active_days = strtoull(l_active_days_str,NULL,10);
                if ( l_active_days ){
                    l_time = DAP_NEW_Z(dap_chain_time_t);
                    *l_time = dap_chain_time_now() + (dap_chain_time_t) l_active_days*86400ull;
                    dap_chain_global_db_gr_set(dap_strdup(l_login_str), l_time,sizeof (*l_time) ,s_group_ts_active_till );
                }else
                    dap_string_append_printf(l_ret_str,"WARNING: Wrong --active_time format\n");
            }

            if (l_is_user_create){
                run_hook(s_hook_user_create, "login=%s pass=%s active_days=%lld first_name=%s last_name=%s email=%s", l_login_str, l_password_str, l_active_days,
                        l_first_name_str ? l_first_name_str : "-",
                        l_last_name_str ? l_last_name_str : "-",
                        l_email_str ? l_email_str : "-");
                dap_string_append_printf(l_ret_str,"OK: Created user '%s'\n",l_login_str );
                l_ret = 0;
            }else if (l_is_user_update){
                run_hook(s_hook_user_update, "login=%s pass=%s active_days=%lld first_name=%s last_name=%s email=%s", l_login_str, l_password_str, l_active_days,
                                        l_first_name_str ? l_first_name_str : "-",
                                        l_last_name_str ? l_last_name_str : "-",
                                        l_email_str ? l_email_str : "-");
                dap_string_append_printf(l_ret_str,"OK: Updated user '%s'\n",l_login_str );
                l_ret = 0;
            }else{
                dap_string_append_printf(l_ret_str,"OK: Unknown action success\n");
                l_ret = 0;
            }
        }else{
            if (l_is_user_create){
                dap_string_append_printf(l_ret_str,"ERROR: Need at least --login and --password options\n" );
                l_ret = -2;
            }else if (l_is_user_update){
                dap_string_append_printf(l_ret_str,"ERROR: Need at least --login and one of next options: --password, --first_name, --last_name or --email\n" );
                l_ret = -3;
            }else{
                dap_string_append_printf(l_ret_str,"ERROR: Unknown error in options\n");
                l_ret = -4;
            }
        }

    }else if ( dap_strcmp(a_user_str, "delete") == 0 ){
        const char * l_login_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "--login", &l_login_str);
        if ( l_login_str ) {
            if ( dap_chain_global_db_gr_del( dap_strdup( l_login_str),s_group_password ) ){
                dap_chain_global_db_gr_del( dap_strdup( l_login_str),s_group_last_name );
                dap_chain_global_db_gr_del( dap_strdup( l_login_str),s_group_first_name );
                dap_chain_global_db_gr_del( dap_strdup( l_login_str),s_group_email );
                dap_chain_global_db_gr_del( dap_strdup( l_login_str),s_group_cookie );

                // Find if present cookie and delete it
                size_t l_cookie_size = 0;
                char * l_cookie = (char*) dap_chain_global_db_gr_get(l_login_str,&l_cookie_size, s_group_cookie );
                if ( l_cookie ){
                    dap_chain_global_db_gr_del( l_cookie,s_group_cookies );
                    log_it(L_WARNING,"Deleted user but its cookie is active in table. Deleted that but better also to close session");
                    // TODO close session when cookie deleted
                }

                dap_string_append_printf(l_ret_str,"OK: Deleted user '%s'\n",l_login_str );
                run_hook(s_hook_user_delete, "login=%s", l_login_str);
                l_ret = 0;
            }else{
                l_ret = -6;
                dap_string_append_printf(l_ret_str,"ERROR: Can't find login '%s' in database\n", l_login_str );
            }
        }else{
            l_ret = -5;
            dap_string_append_printf(l_ret_str,"ERROR: Need --login option\n" );
        }
    }else if ( dap_strcmp(a_user_str, "check") == 0 ){
        const char * l_login_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "--login", &l_login_str);
        const char * l_password_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "--password", &l_password_str);
        if ( l_login_str && l_password_str) {
            int l_check = dap_chain_net_srv_vpn_cdb_auth_check_login (l_login_str, l_password_str);
            if ( l_check == 0){
                dap_string_append_printf(l_ret_str,"OK: Passed password check for '%s'\n",l_login_str );
                l_ret = 0;
            }else if (l_check == -1){
                l_ret = -7;
                dap_string_append_printf(l_ret_str,"ERROR: Can't find login '%s' in database\n", l_login_str );
            }else if (l_check == -2){
                l_ret = -8;
                dap_string_append_printf(l_ret_str,"ERROR: Wrong password for login '%s'\n", l_login_str );
            }else if (l_check == -3){
                l_ret = -10;
                dap_string_append_printf(l_ret_str,"ERROR: Login '%s' is not activated\n", l_login_str );
            }else if (l_check == -4){
                l_ret = -11;
                dap_string_append_printf(l_ret_str,"ERROR: Login '%s' activation is overdue\n", l_login_str );
            }else {
                l_ret = -9;
                dap_string_append_printf(l_ret_str,"ERROR: Unknown error in password check for login '%s'\n", l_login_str );
            }
        }else{
            l_ret = -5;
            dap_string_append_printf(l_ret_str,"ERROR: Need --login option\n" );
        }
    }else if ( dap_strcmp(a_user_str, "show") == 0 ){
        const char * l_login_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "--login", &l_login_str);
        if ( l_login_str ) {
            size_t l_password_hash_size=0;
            dap_chain_hash_fast_t *l_password_hash;
            if ( (l_password_hash = (dap_chain_hash_fast_t*) dap_chain_global_db_gr_get (
                     l_login_str,&l_password_hash_size  ,s_group_password ) ) !=NULL ){
                dap_string_append_printf(l_ret_str,"OK: Find user '%s'\n",l_login_str );

                size_t l_first_name_size=0;
                char * l_first_name =(char *) dap_chain_global_db_gr_get (  l_login_str,&l_first_name_size  ,s_group_first_name ) ;
                if ( l_first_name ){
                    dap_string_append_printf(l_ret_str,"\tFirst_name: %s\n", l_first_name);
                    DAP_DELETE( l_first_name );
                }

                size_t l_last_name_size=0;
                char * l_last_name =(char *) dap_chain_global_db_gr_get (  l_login_str,&l_last_name_size  ,s_group_last_name ) ;
                if (l_last_name){
                    dap_string_append_printf(l_ret_str,"\tLast_name: %s\n", l_last_name);
                    DAP_DELETE( l_last_name );
                }

                size_t l_email_size=0;
                char * l_email =(char *) dap_chain_global_db_gr_get (  l_login_str,&l_email_size  ,s_group_email ) ;
                if (l_email){
                    dap_string_append_printf(l_ret_str,"\tEmail: %s\n", l_email);
                    DAP_DELETE( l_email );
                }

                size_t l_ts_active_till_size = 0;
                time_t *l_ts_active_till = (time_t*) dap_chain_global_db_gr_get(l_login_str, &l_ts_active_till_size, s_group_ts_active_till);
                if(l_ts_active_till_size) {
                    double l_dt_days = difftime(*l_ts_active_till, time(NULL)) / 86400;

                    if(l_dt_days < 1) {
                        if(l_dt_days < 0)
                            l_dt_days = 0;
                        dap_string_append_printf(l_ret_str, "\tActive hours: %.2lf\n", l_dt_days * 24);
                    }
                    else
                        dap_string_append_printf(l_ret_str, "\tActive days: %.2lf\n", l_dt_days);
                    DAP_DELETE(l_ts_active_till);
                }

                l_ret = 0;
            }else{
                l_ret = -6;
                dap_string_append_printf(l_ret_str,"ERROR: Can't find login '%s' in database\n", l_login_str );
            }
        }else{
            l_ret = -5;
            dap_string_append_printf(l_ret_str,"ERROR: Need --login option\n" );
        }
    }else if ( dap_strcmp(a_user_str, "list") == 0 ){
        size_t l_users_size = 0;
        dap_global_db_obj_t* l_users = dap_chain_global_db_gr_load(s_group_password,&l_users_size);
        if (l_users_size){
            dap_string_append_printf(l_ret_str,"OK: %zd users in DB\n",l_users_size);
            for ( size_t i = 0; i < l_users_size; i++ ){
                dap_string_append_printf(l_ret_str,"\t%s\n",l_users[i].key);
            }
            dap_chain_global_db_objs_delete(l_users, l_users_size);
        }else{
            dap_string_append_printf(l_ret_str,"OK: 0 users in DB\n");
        }
    }else {
        dap_string_append_printf(l_ret_str,"ERROR: Unknown command 'user %s'\n", a_user_str );
        l_ret = -1;
    }
    dap_chain_node_cli_set_reply_text( a_str_reply, l_ret_str->str );
    dap_string_free( l_ret_str, false );
    return l_ret;
}


void dap_chain_net_srv_vpn_cdb_auth_add_proc(dap_http_t * a_http, const char * a_url)
{
    dap_http_simple_proc_add(a_http,a_url,24000, s_http_proc);
}

/**
 * @brief s_http_proc Process auth request
 * @param sh HTTP simple client instance
 * @param arg Return if ok
 */
static void s_http_proc(dap_http_simple_t *a_http_simple, void * arg )
{
    http_status_code_t * return_code = (http_status_code_t*)arg;
    enc_http_delegate_t * l_delegate;
    strcpy(a_http_simple->reply_mime,"application/octet-stream");

    l_delegate = enc_http_request_decode(a_http_simple);
    if(l_delegate){
        if(strcmp(l_delegate->url_path, "auth") == 0) {
            s_http_enc_proc(l_delegate, arg);
        }
        else if(strcmp(l_delegate->url_path, "auth_key") == 0) {
            s_http_enc_proc_key(l_delegate, arg);
        }
        else {

            if(l_delegate->url_path)
                log_it(L_ERROR,"Wrong auth request %s",l_delegate->url_path);
            else
                log_it(L_ERROR,"Wrong auth request: nothing after / ");

            *return_code = Http_Status_BadRequest;
        }

        enc_http_reply_encode(a_http_simple,l_delegate);
        enc_http_delegate_delete(l_delegate);
    }else{
        *return_code = Http_Status_Unauthorized;
        log_it(L_WARNING,"No KeyID in the request");
    }
}

/**
 * @brief s_http_enc_proc Auth http interface
 * @param a_delegate HTTP Simple client instance
 * @param a_arg Pointer to bool with okay status (true if everything is ok, by default)
 */
static void s_http_enc_proc(enc_http_delegate_t *a_delegate, void * a_arg)
{
    http_status_code_t * l_return_code = (http_status_code_t*)a_arg;

    if((a_delegate->request)&&(strcmp(a_delegate->action,"POST")==0)){
        if(a_delegate->in_query==NULL){
            log_it(L_WARNING,"Empty auth action");
            *l_return_code = Http_Status_BadRequest;
            return;
        }else{
            if(strcmp(a_delegate->in_query,"logout")==0 ){
                if(dap_chain_global_db_gr_del(dap_strdup( a_delegate->cookie), s_group_cookies)){
                    enc_http_reply_f(a_delegate,
                                     "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n"
                                     "<return>Successfuly logouted</return>\n"
                                     );
                    *l_return_code = Http_Status_OK;
                }else{
                    log_it(L_NOTICE,"Logout action: cookie %s is already logouted (by timeout?)", a_delegate->cookie);
                    enc_http_reply_f(a_delegate,
                                     "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n"
                                     "<err_str>No session in table</err_str>\n"
                                     );
                    *l_return_code = Http_Status_OK;
                }

            }else if(strcmp(a_delegate->in_query,"login")==0 || strcmp(a_delegate->in_query,"serial")==0 ){
                char l_login[128]={0};
                char l_password[256]={0};
                char l_pkey[6001]={0};//char l_pkey[4096]={0};

                char l_domain[64], l_domain2[64];

                //log_it(L_DEBUG, "request_size=%d request_str='%s'\n",a_delegate->request_size, a_delegate->request_str);

                // password mode
                if(s_mode_passwd) {
                    if(sscanf(a_delegate->request_str, "%127s %255s %63s %6000s %63s", l_login, l_password, l_domain,
                            l_pkey, l_domain2) >= 4 ||
                            sscanf(a_delegate->request_str, "%127s %255s %6000s ", l_login, l_password, l_pkey) >= 3) {
                        log_it(L_INFO, "Trying to login with username '%s'", l_login);

                        if(s_input_validation(l_login) == 0) {
                            log_it(L_WARNING, "Wrong symbols in username");
                            enc_http_reply_f(a_delegate, OP_CODE_INCORRECT_SYMOLS);
                            *l_return_code = Http_Status_BadRequest;
                            return;
                        }
                        if(s_input_validation(l_password) == 0) {
                            log_it(L_WARNING, "Wrong symbols in password");
                            enc_http_reply_f(a_delegate, OP_CODE_INCORRECT_SYMOLS);
                            *l_return_code = Http_Status_BadRequest;
                            return;
                        }
                        if(s_input_validation(l_pkey) == 0) {
                            log_it(L_WARNING, "Wrong symbols in base64 pkey string");
                            enc_http_reply_f(a_delegate, OP_CODE_INCORRECT_SYMOLS);
                            *l_return_code = Http_Status_BadRequest;
                            return;
                        }

                        int l_login_result = dap_chain_net_srv_vpn_cdb_auth_check_login(l_login, l_password);
                        run_hook(s_hook_user_login, "login=%s pass=%s result=%d", l_login, l_password, l_login_result);
                        switch (l_login_result) {
                        case 0: {
                            size_t l_tmp_size;
                            char * l_first_name = (char*) dap_chain_global_db_gr_get(l_login, &l_tmp_size,
                                    s_group_first_name);
                            char * l_last_name = (char*) dap_chain_global_db_gr_get(l_login, &l_tmp_size,
                                    s_group_last_name);
                            char * l_email = (char*) dap_chain_global_db_gr_get(l_login, &l_tmp_size, s_group_email);
                            dap_chain_time_t * l_ts_last_logined = (dap_chain_time_t*) dap_chain_global_db_gr_get(
                                    l_login, &l_tmp_size, s_group_ts_last_login);
                            dap_chain_time_t *l_ts_active_till = (dap_chain_time_t*) dap_chain_global_db_gr_get(l_login,
                                    &l_tmp_size, s_group_ts_active_till);

                            enc_http_reply_f(a_delegate,
                                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n"
                                            "<auth_info>\n"
                                    );
                            enc_http_reply_f(a_delegate, "\t<login>%s</login>\n", l_login);
                            if(l_first_name)
                                enc_http_reply_f(a_delegate, "\t<first_name>%s</first_name>\n", l_first_name);
                            if(l_last_name)
                                enc_http_reply_f(a_delegate, "\t<last_name>%s</last_name>\n", l_last_name);
                            if(l_email)
                                enc_http_reply_f(a_delegate, "\t<email>%s</email>\n", l_email);
                            if(l_ts_last_logined)
                                enc_http_reply_f(a_delegate, "\t<ts_prev_login>%llu</ts_prev_login>\n", (long long unsigned) *l_ts_last_logined);
                            if(l_ts_active_till)
                                enc_http_reply_f(a_delegate, "\t<ts_active_till>%llu</ts_acyive_till>\n", (long long unsigned) *l_ts_active_till);

                            if(a_delegate->cookie)
                                enc_http_reply_f(a_delegate, "\t<cookie>%s</cookie>\n", a_delegate->cookie);
                            dap_chain_net_srv_vpn_cdb_auth_after(a_delegate, l_login, l_pkey); // Here if smbd want to add smth to the output
                            enc_http_reply_f(a_delegate, "</auth_info>");
                            log_it(L_INFO, "Login: Successfuly logined user %s", l_login);
                            *l_return_code = Http_Status_OK;
                            //log_it(L_DEBUG, "response_size='%d'",a_delegate->response_size);
                            DAP_DELETE(l_first_name);
                            DAP_DELETE(l_last_name);
                            DAP_DELETE(l_email);
                            DAP_DELETE(l_ts_last_logined);
                            DAP_DELETE(l_ts_active_till);

                            // Update last logined
                            l_ts_last_logined = DAP_NEW_Z(dap_chain_time_t);
                            *l_ts_last_logined = dap_chain_time_now();
                            dap_chain_global_db_gr_set(dap_strdup(l_login), l_ts_last_logined, sizeof(time_t), s_group_ts_last_login);
                            DAP_DELETE(l_ts_last_logined);
                        }
                            break;
                        case -1:
                            enc_http_reply_f(a_delegate, OP_CODE_NOT_FOUND_LOGIN_IN_DB);
                            *l_return_code = Http_Status_OK;
                            break;
                        case -2:
                            enc_http_reply_f(a_delegate, OP_CODE_LOGIN_INCORRECT_PSWD);
                            *l_return_code = Http_Status_OK;
                            break;
                        case -3:
                            enc_http_reply_f(a_delegate, OP_CODE_LOGIN_INACTIVE);
                            *l_return_code = Http_Status_OK;
                            break;
                        case -4:
                            enc_http_reply_f(a_delegate, OP_CODE_SUBSCRIBE_EXPIRIED);
                            *l_return_code = Http_Status_PaymentRequired;
                            break;
                        default:
                            log_it(L_WARNING, "Login: Unknown authorize error for login '%s'", l_login);
                            *l_return_code = Http_Status_BadRequest;
                            break;
                        }
                    } else {
                        log_it(L_DEBUG, "Login: wrong auth's request body ");
                        *l_return_code = Http_Status_BadRequest;
                    }
                }
                // serial mode
                else
                {
                    char l_serial_tmp[64]={0};
                    if(sscanf(a_delegate->request_str, "%63s %63s %6000s", l_serial_tmp, l_domain, l_pkey) >= 3) {
                        char *l_serial = make_fullserial(l_serial_tmp);
                        log_it(L_INFO, "Trying to login with serial '%s'", l_serial);
                        if(s_input_validation(l_serial) == 0) {
                            log_it(L_WARNING, "Wrong symbols in serial");
                            enc_http_reply_f(a_delegate, OP_CODE_INCORRECT_SYMOLS);
                            *l_return_code = Http_Status_BadRequest;
                            DAP_DELETE(l_serial);
                            return;
                        }
                        if(s_input_validation(l_domain) == 0) {
                            log_it(L_WARNING, "Wrong symbols in l_domain");
                            enc_http_reply_f(a_delegate, OP_CODE_INCORRECT_SYMOLS);
                            *l_return_code = Http_Status_BadRequest;
                            DAP_DELETE(l_serial);
                            return;
                        }
                        if(s_input_validation(l_pkey) == 0) {
                            log_it(L_WARNING, "Wrong symbols in base64 pkey string");
                            enc_http_reply_f(a_delegate, OP_CODE_INCORRECT_SYMOLS);
                            *l_return_code = Http_Status_BadRequest;
                            DAP_DELETE(l_serial);
                            return;
                        }
                        int l_login_result = dap_chain_net_srv_vpn_cdb_auth_check_serial(l_serial, l_pkey);
                        log_it(L_INFO, "Check serial '%s' with code %d (Ok=0)", l_serial, l_login_result);
                        run_hook(s_hook_serial_login, "serial=%s result=%d", l_serial, l_login_result);
                        switch (l_login_result) {
                        case 0: {
                            size_t l_tmp_size;
                            enc_http_reply_f(a_delegate,
                                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n"
                                            "<auth_info>\n"
                                    );
                            enc_http_reply_f(a_delegate, "\t<serial>%s</serial>\n", l_serial);

                            dap_chain_time_t * l_ts_last_logined = (dap_chain_time_t*) dap_chain_global_db_gr_get(l_serial, &l_tmp_size, s_group_ts_last_login);
                            dap_chain_time_t *l_ts_active_till = (dap_chain_time_t*) dap_chain_global_db_gr_get(l_serial, &l_tmp_size, s_group_ts_active_till);
                            if(l_ts_last_logined)
                                enc_http_reply_f(a_delegate, "\t<ts_prev_login>%llu</ts_prev_login>\n", (long long unsigned) *l_ts_last_logined);
                            if(l_ts_active_till)
                                enc_http_reply_f(a_delegate, "\t<ts_active_till>%llu</ts_acyive_till>\n", (long long unsigned) *l_ts_active_till);
                            if(a_delegate->cookie)
                                enc_http_reply_f(a_delegate, "\t<cookie>%s</cookie>\n", a_delegate->cookie);
                            dap_chain_net_srv_vpn_cdb_auth_after(a_delegate, l_serial, l_pkey); // Here if smbd want to add smth to the output
                            enc_http_reply_f(a_delegate, "</auth_info>");
                            log_it(L_INFO, "Login: Successfuly logined user %s", l_login);
                            *l_return_code = Http_Status_OK;
                            //log_it(L_DEBUG, "response_size='%d'",a_delegate->response_size);

                            DAP_DELETE(l_ts_last_logined);
                            DAP_DELETE(l_ts_active_till);

                            // Update last logined
                            l_ts_last_logined = DAP_NEW_Z(dap_chain_time_t);
                            *l_ts_last_logined = dap_chain_time_now();
                            dap_chain_global_db_gr_set(dap_strdup(l_serial), l_ts_last_logined, sizeof(time_t),s_group_ts_last_login);
                            DAP_DELETE(l_ts_last_logined);
                        }
                            break;
                        case -1:
                            enc_http_reply_f(a_delegate, OP_CODE_NOT_FOUND_LOGIN_IN_DB);
                            *l_return_code = Http_Status_OK;
                            break;
                        case -2:
                            enc_http_reply_f(a_delegate, OP_CODE_LOGIN_INCORRECT_SIGN);// incorrect pkey
                            *l_return_code = Http_Status_OK;
                            break;
                        case -3:
                            enc_http_reply_f(a_delegate, OP_CODE_LOGIN_INACTIVE);
                            *l_return_code = Http_Status_OK;
                            break;
                        case -4:
                            enc_http_reply_f(a_delegate, OP_CODE_SUBSCRIBE_EXPIRIED);
                            *l_return_code = Http_Status_PaymentRequired;
                            break;
                        default:
                            log_it(L_WARNING, "Login: Unknown authorize error for login '%s'", l_login);
                            *l_return_code = Http_Status_BadRequest;
                            break;
                        }
                        DAP_DELETE(l_serial);
                    }
                }
            }else if (s_is_registration_open && strcmp(a_delegate->in_query,"register")==0){
                char l_login[128];
                char l_password[256];
                char l_first_name[128];
                char l_last_name[128];
                char l_email[256];

                log_it(L_INFO, "Request str = %s", a_delegate->request_str);
                if(sscanf(a_delegate->request_str,"%127s %255s %127s %127s %255s"
                          ,l_login,l_password,l_email,l_first_name,l_last_name)>=3){
                    if(s_input_validation(l_login)==0){
                        log_it(L_WARNING,"Registration: Wrong symbols in the username '%s'",l_login);
                        *l_return_code = Http_Status_BadRequest;
                        return;
                    }
                    if(s_input_validation(l_password)==0){
                        log_it(L_WARNING,"Registration: Wrong symbols in the password");
                        *l_return_code = Http_Status_BadRequest;
                        return;
                    }
                    if(s_input_validation(l_first_name)==0){
                        log_it(L_WARNING,"Registration: Wrong symbols in the first name '%s'",l_first_name);
                        *l_return_code = Http_Status_BadRequest;
                        return;
                    }
                    if(s_input_validation(l_last_name)==0){
                        log_it(L_WARNING,"Registration: Wrong symbols in the last name '%s'",l_last_name);
                        *l_return_code = Http_Status_BadRequest;
                        return;
                    }
                    if(s_input_validation(l_email)==0){
                        log_it(L_WARNING,"Registration: Wrong symbols in the email '%s'",l_email);
                        *l_return_code = Http_Status_BadRequest;
                        return;
                    }
                    if ( l_login[0] && l_password[0] && l_email[0] ){

                        // Hash password with salt
                        char * l_hash_str = dap_strdup_printf("%s%s",l_password, s_salt_str );
                        dap_chain_hash_fast_t *l_password_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
                        dap_hash_fast(l_hash_str,dap_strlen(l_hash_str), l_password_hash );
                        DAP_DELETE(l_hash_str);
                        dap_chain_global_db_gr_set(dap_strdup(l_login), l_password_hash,sizeof(*l_password_hash),s_group_password );

                        // Write email in db
                        dap_chain_global_db_gr_set(dap_strdup(l_login), dap_strdup(l_email),strlen(l_email)+1,s_group_email );

                        enc_http_reply_f(a_delegate,
                                         "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n"
                                         "<auth_info>\n"
                                         );

                        enc_http_reply_f(a_delegate,"\t<login>%s</login>\n",l_login);
                        // Write first and last names in db if present
                        if ( l_first_name[0] ){
                            dap_chain_global_db_gr_set( dap_strdup(l_login), dap_strdup(l_first_name),strlen(l_first_name)+1,
                                                        s_group_first_name );
                            enc_http_reply_f(a_delegate,"\t<first_name>%s</first_name>\n",l_first_name);
                        }

                        if ( l_last_name[0] ){
                            dap_chain_global_db_gr_set( dap_strdup(l_login), dap_strdup( l_last_name ), strlen( l_last_name)+1,
                                                        s_group_last_name );
                            enc_http_reply_f(a_delegate,"\t<last_name>%s</last_name>\n",l_last_name);
                        }

                        // If cookie present - report it
                        if ( a_delegate->cookie )
                            enc_http_reply_f(a_delegate,"\t<cookie>%s</cookie>\n",a_delegate->cookie );
                        enc_http_reply_f(a_delegate,"</auth_info>");

                        log_it(L_NOTICE,"Registration: new user %s \"%s %s\"<%s> is registred",l_login,l_first_name,l_last_name,l_email);
                    }
                }else{
                    log_it(L_ERROR, "Registration: Wrong auth's request body ");
                    *l_return_code = Http_Status_BadRequest;
                }
            }else{
                log_it(L_ERROR, "Unknown auth command was selected (query_string='%s')",a_delegate->in_query);
                *l_return_code = Http_Status_BadRequest;
            }
        }
    }else{
        log_it(L_ERROR, "Wrong auth request action '%s'",a_delegate->action);
        *l_return_code = Http_Status_BadRequest;
    }
}

/**
 * @brief s_http_enc_proc Auth http interface
 * @param a_delegate HTTP Simple client instance
 * @param a_arg Pointer to bool with okay status (true if everything is ok, by default)
 */
static void s_http_enc_proc_key(enc_http_delegate_t *a_delegate, void * a_arg)
{
    http_status_code_t * l_return_code = (http_status_code_t*) a_arg;

    if((a_delegate->request) && (strcmp(a_delegate->action, "POST") == 0)) {
        if(a_delegate->in_query == NULL) {
            log_it(L_WARNING, "Empty auth action");
            *l_return_code = Http_Status_BadRequest;
            return;
        } else {
            if(strcmp(a_delegate->in_query, "serial") == 0) {
                char l_serial_raw[64] = { 0 };
                char l_serial_sign[12000] = { 0 };
                char l_pkey[6001] = { 0 };

                // only for serial mode
                if(!s_mode_passwd)
                {
                    char l_domain[64];
                    if(sscanf(a_delegate->request_str, "%63s %12000s %63s %6000s", l_serial_raw, l_serial_sign, l_domain, l_pkey) >= 4) {
                        char *l_serial = make_fullserial(l_serial_raw);
                        /*size_t a1 = dap_strlen(l_serial);
                        size_t a2 = dap_strlen(l_serial_sign);
                        size_t a3 = dap_strlen(l_pkey);*/
                        log_it(L_INFO, "Trying to activate with serial '%s'", l_serial);
                        if(s_input_validation(l_serial) == 0) {
                            log_it(L_WARNING, "Wrong symbols in serial");
                            enc_http_reply_f(a_delegate, OP_CODE_INCORRECT_SYMOLS);
                            *l_return_code = Http_Status_BadRequest;
                            DAP_DELETE(l_serial);
                            return;
                        }
                        if(s_input_validation(l_pkey) == 0) {
                            log_it(L_WARNING, "Wrong symbols in base64 pkey string");
                            enc_http_reply_f(a_delegate, OP_CODE_INCORRECT_SYMOLS);
                            *l_return_code = Http_Status_BadRequest;
                            DAP_DELETE(l_serial);
                            return;
                        }
                        if(s_input_validation(l_serial_sign) == 0) {
                            log_it(L_WARNING, "Wrong symbols in base64 serial sign");
                            enc_http_reply_f(a_delegate, OP_CODE_INCORRECT_SYMOLS);
                            *l_return_code = Http_Status_BadRequest;
                            DAP_DELETE(l_serial);
                            return;
                        }
                        int l_activate_result = dap_chain_net_srv_vpn_cdb_auth_activate_serial(l_serial_raw, l_serial, l_serial_sign, l_pkey);
                        run_hook(s_hook_serial_activate, "serial=%s result=%d", l_serial, l_activate_result);
                        log_it(L_INFO, "Serial '%s' activated with code %d (Ok=0)", l_serial, l_activate_result);
                        switch (l_activate_result) {
                        case 0:
                            enc_http_reply_f(a_delegate, OP_CODE_SERIAL_ACTIVED);
                            *l_return_code = Http_Status_OK;
                            break;
                        case -1:
                            enc_http_reply_f(a_delegate, OP_CODE_NOT_FOUND_LOGIN_IN_DB);
                            *l_return_code = Http_Status_OK;
                            break;
                        case -2:
                            enc_http_reply_f(a_delegate, OP_CODE_LOGIN_INCORRECT_SIGN);
                            *l_return_code = Http_Status_OK;
                            break;
                            /*case -3:
                             enc_http_reply_f(a_delegate, OP_CODE_LOGIN_INACTIVE);
                             *l_return_code = Http_Status_OK;
                             break;*/
                        case -4:
                            enc_http_reply_f(a_delegate, OP_CODE_SUBSCRIBE_EXPIRIED);
                            *l_return_code = Http_Status_PaymentRequired;
                            break;
                        default:
                            log_it(L_WARNING, "Login: Unknown authorize error for activate serial '%s'", l_serial);
                            *l_return_code = Http_Status_BadRequest;
                            break;
                        }
                        DAP_DELETE(l_serial);
                    }
                    else {
                        log_it(L_ERROR, "Registration: Wrong auth_key's request body ");
                        *l_return_code = Http_Status_BadRequest;
                    }
                }
            } else {
                log_it(L_ERROR, "Unknown auth command was selected (query_string='%s')", a_delegate->in_query);
                *l_return_code = Http_Status_BadRequest;
            }
        }
    } else {
        log_it(L_ERROR, "Wrong auth request action '%s'", a_delegate->action);
        *l_return_code = Http_Status_BadRequest;
    }
}
