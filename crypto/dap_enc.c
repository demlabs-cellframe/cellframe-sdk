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
 * @brief dap_enc_code Encode data with key
 * @param key_private Private key
 * @param buf  Input buffer
 * @param buf_size Input buffer size
 * @param buf_out Output buffer
 * @return bytes actualy written in the output buffer
 */
size_t dap_enc_code(struct dap_enc_key * key,const void * buf,const size_t buf_size,
                    void ** buf_out, dap_enc_data_type_t data_type_out)
{
    if(key->enc) {
        if(data_type_out == DAP_ENC_DATA_TYPE_RAW) {
            return key->enc(key, buf, buf_size, buf_out);
        }

        void *proc_buf;
        size_t ret = key->enc(key, buf, buf_size, &proc_buf);
        if(data_type_out == DAP_ENC_DATA_TYPE_B64 || data_type_out == DAP_ENC_DATA_TYPE_B64_URLSAFE) {
            *buf_out = malloc(DAP_ENC_BASE64_ENCODE_SIZE(ret));
            ret=dap_enc_base64_encode(proc_buf, ret, *buf_out, data_type_out);
            free(proc_buf);
        } else {
            log_it(L_ERROR, "Unknown dap_enc_data_type");
            return 0;
        }
        return ret;
    } else {
        log_it(L_ERROR, "key->enc is NULL");
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
size_t dap_enc_decode(struct dap_enc_key * key,const void * buf, const size_t buf_size,
                      void ** buf_out, dap_enc_data_type_t data_type_in)
{
    void *proc_buf = NULL;
    const void *proc_buf_const = NULL;
    size_t proc_buf_size = 0;
    switch(data_type_in){
        case DAP_ENC_DATA_TYPE_B64:
        case DAP_ENC_DATA_TYPE_B64_URLSAFE:
            proc_buf=calloc(1,DAP_ENC_BASE64_ENCODE_SIZE(buf_size));
            proc_buf_size= dap_enc_base64_decode((const char*) buf,buf_size,proc_buf,data_type_in);
            proc_buf_const=proc_buf;
        break;
        case DAP_ENC_DATA_TYPE_RAW:{
            proc_buf_const=buf;
            proc_buf_size=buf_size;
        }break;
    }

    if(key->dec) {
        if(proc_buf_size == 0) {
            log_it(L_ERROR, "Buf is null. dap_enc_base64_decode is failed");
            return 0;
        }
        size_t ret = key->dec(key,proc_buf_const,proc_buf_size, buf_out);

        if(data_type_in==DAP_ENC_DATA_TYPE_B64 || data_type_in == DAP_ENC_DATA_TYPE_B64_URLSAFE)
            free(proc_buf);
        return ret;
    } else {
        log_it(L_WARNING, "key->dec is NULL");
        if(proc_buf_size)
            free(proc_buf);
        return 0;
    }
}
