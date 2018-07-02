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


#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "dap_enc.h"
#include "dap_enc_base64.h"
#include "dap_enc_key.h"
#include "dap_common.h"
#include "dap_enc_msrln16.h"

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
size_t dap_enc_code(struct dap_enc_key * key,const void * buf,const size_t buf_size, void * buf_out, dap_enc_data_type_t data_type_out)
{
    if(key->enc){
        void *proc_buf = NULL;
        if(data_type_out == DAP_ENC_DATA_TYPE_RAW)
            proc_buf=buf_out;
        else
            proc_buf=calloc(1,buf_size*2);
        size_t ret=key->enc(key,buf,buf_size,proc_buf);
        if(data_type_out==DAP_ENC_DATA_TYPE_B64){
            ret=dap_enc_base64_encode(proc_buf,ret,buf_out,DAP_ENC_STANDARD_B64);
            if (proc_buf)
            	free(proc_buf);
        }else if(data_type_out == DAP_ENC_DATA_TYPE_B64_URLSAFE){
            ret=dap_enc_base64_encode(proc_buf,ret,buf_out,DAP_ENC_STANDARD_B64_URLSAFE);
            if (proc_buf)
            	free(proc_buf);
        }
        return ret;
    }else{
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
size_t dap_enc_decode(struct dap_enc_key * key,const void * buf, const size_t buf_size, void * buf_out, dap_enc_data_type_t data_type_in)
{
    void *proc_buf = NULL;
    const void *proc_buf_const = NULL;
    size_t proc_buf_size = 0;
    switch(data_type_in){
        case DAP_ENC_DATA_TYPE_B64_URLSAFE:{
            proc_buf=calloc(1,buf_size);
            proc_buf_size= dap_enc_base64_decode((const char*) buf,buf_size,proc_buf,DAP_ENC_STANDARD_B64_URLSAFE);
            proc_buf_const=proc_buf;
        }break;
        case DAP_ENC_DATA_TYPE_B64:{
            proc_buf=calloc(1,buf_size);
            proc_buf_size= dap_enc_base64_decode((const char*) buf,buf_size,proc_buf,DAP_ENC_STANDARD_B64);
            proc_buf_const=proc_buf;
        }break;
        case DAP_ENC_DATA_TYPE_RAW:{
            proc_buf_const=buf;
            proc_buf_size=buf_size;
        }break;
    }

    if(key->dec){
        size_t ret=key->dec(key,proc_buf_const,proc_buf_size,buf_out);
        if(data_type_in==DAP_ENC_DATA_TYPE_B64 || DAP_ENC_DATA_TYPE_B64_URLSAFE)
        	if (proc_buf)
        		free(proc_buf);
        return ret;
    }else{
        return 0;
    }
}
