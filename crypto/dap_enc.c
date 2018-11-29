/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef _WIN32
#include <arpa/inet.h>
#endif
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "dap_enc.h"
#include "dap_enc_base64.h"
#include "dap_enc_key.h"
#include "dap_common.h"

#define LOG_TAG "dap_enc"

/**
 * @brief enc_init
 * @return
 */
int dap_enc_init()
{
    srand(time(NULL));
    return 0;
}

/**
 * @brief dap_enc_deinit
 */
void dap_enc_deinit()
{

}

/**
 * @brief dap_enc_code_out_size
 * @param a_key
 * @param a_buf_in_size
 * @return min buffer size for input in encode function
 */
size_t dap_enc_code_out_size(dap_enc_key_t* a_key, const size_t a_buf_in_size, dap_enc_data_type_t type)
{
    size_t raw_encode_data_size = dap_enc_key_get_enc_size(a_key, a_buf_in_size);
    if(raw_encode_data_size == 0) {
        log_it(L_ERROR, "dap_enc_key_get_enc_size return 0");
        return 0;
    }
    if(type != DAP_ENC_DATA_TYPE_RAW) {
        return (size_t)DAP_ENC_BASE64_ENCODE_SIZE(raw_encode_data_size);
    }
    return raw_encode_data_size;
}

/**
 * @brief dap_enc_decode_out_size
 * @param a_key
 * @param a_buf_in_size
 * @return min buffer size for input in decode function
 */
size_t dap_enc_decode_out_size(dap_enc_key_t* a_key, const size_t a_buf_in_size, dap_enc_data_type_t type)
{
    size_t raw_decode_data_size = dap_enc_key_get_dec_size(a_key, a_buf_in_size);
    if(raw_decode_data_size == 0) {
        log_it(L_ERROR, "dap_enc_key_get_enc_size return 0");
        return 0;
    }

    if(type != DAP_ENC_DATA_TYPE_RAW) {
        return (size_t)DAP_ENC_BASE64_ENCODE_SIZE(raw_decode_data_size);
    }
    return raw_decode_data_size;
}



/**
 * @brief dap_enc_code Encode data with key
 * @param a_key Private key
 * @param a_buf  Input buffer
 * @param a_buf_size Input buffer size
 * @param a_buf_out Output buffer
 * @param a_buf_out_size_max
 * @return bytes actualy written in the output buffer
 */
size_t dap_enc_code(struct dap_enc_key * a_key,const void * a_buf_in,const size_t a_buf_size,
                    void * a_buf_out, const size_t a_buf_out_size_max, dap_enc_data_type_t a_data_type_out)
{
    if(a_key->enc_na) {
        if(a_data_type_out == DAP_ENC_DATA_TYPE_RAW) {
            return a_key->enc_na(a_key, a_buf_in, a_buf_size, a_buf_out, a_buf_out_size_max);
        }else{
            void *l_proc_buf;
            l_proc_buf  = DAP_NEW_SIZE (void, a_buf_out_size_max );
            size_t l_proc_buf_size = a_key->enc_na(a_key, a_buf_in, a_buf_size, l_proc_buf,a_buf_out_size_max);
            if(a_data_type_out == DAP_ENC_DATA_TYPE_B64 || a_data_type_out == DAP_ENC_DATA_TYPE_B64_URLSAFE) {
                if(DAP_ENC_BASE64_ENCODE_SIZE(l_proc_buf_size) <= a_buf_out_size_max) {
                    size_t l_buf_out_size=dap_enc_base64_encode(l_proc_buf, l_proc_buf_size, a_buf_out, a_data_type_out);
                    DAP_DELETE(l_proc_buf);
                    return l_buf_out_size;
                } else {
                    DAP_DELETE(l_proc_buf);
                    log_it(L_ERROR, "a_buf_out_size_max less than result size");
                    return 0;
                }
            } else {
                log_it(L_ERROR, "Unknown dap_enc_data_type");
                DAP_DELETE(l_proc_buf);
                return 0;
            }
        }
    } else {
        log_it(L_ERROR, "key->enc_na is NULL");
        return 0;
    }
}

/**
 * @brief dap_enc_decode Decode data with key
 * @param key_public Public key
 * @param buf  Input buffer
 * @param buf_size Input buffer size
 * @param buf_out Output buffer
 * @param buf_out_max Maximum size of output buffer
 * @return bytes actualy written in the output buffer
 */
size_t dap_enc_decode(struct dap_enc_key * a_key,const void * a_buf_in, const size_t a_buf_in_size,
                      void * a_buf_out, const size_t a_buf_out_size_max, dap_enc_data_type_t a_data_type_in)
{
    void *l_proc_buf = NULL;
    const void *l_proc_buf_const = NULL;
    size_t l_proc_buf_size = 0;
    switch(a_data_type_in){
        case DAP_ENC_DATA_TYPE_B64:
        case DAP_ENC_DATA_TYPE_B64_URLSAFE:
            l_proc_buf=DAP_NEW_SIZE(void,DAP_ENC_BASE64_ENCODE_SIZE(a_buf_in_size));
            l_proc_buf_size= dap_enc_base64_decode((const char*) a_buf_in,a_buf_in_size,l_proc_buf,a_data_type_in);
            l_proc_buf_const=l_proc_buf;
        break;
        case DAP_ENC_DATA_TYPE_RAW:{
            l_proc_buf_const=a_buf_in;
            l_proc_buf_size=a_buf_in_size;
        }break;
    }

    if(a_key->dec_na) {
        if(l_proc_buf_size == 0) {
            log_it(L_ERROR, "Buf is null. dap_enc_base64_decode is failed");
            return 0;
        }
        size_t ret = a_key->dec_na(a_key,l_proc_buf_const,l_proc_buf_size, a_buf_out,a_buf_out_size_max);

        if(a_data_type_in==DAP_ENC_DATA_TYPE_B64 || a_data_type_in == DAP_ENC_DATA_TYPE_B64_URLSAFE)
            free(l_proc_buf);
        return ret;
    } else {
        log_it(L_WARNING, "key->dec_na is NULL");
        if(l_proc_buf_size)
            free(l_proc_buf);
        return 0;
    }
}
