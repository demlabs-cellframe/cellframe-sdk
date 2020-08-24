/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * Anatolii Kurotych <akurotych@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
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

#ifndef _DAP_ENC_BASE64_H_
#define _DAP_ENC_BASE64_H_
#include <stddef.h>
#include "dap_enc_key.h"
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Calculates encode size from input size
 */
#define DAP_ENC_BASE64_ENCODE_SIZE(in_size) (size_t)(((4 * in_size / 3) + 3) & ~3)

size_t dap_enc_base64_decode(const char * in, size_t in_size, void * out, dap_enc_data_type_t standard);
size_t dap_enc_base64_encode(const void * in, size_t in_size, char * out, dap_enc_data_type_t standard);
char * dap_enc_strdup_to_base64(const char * a_string);
char * dap_enc_strdup_from_base64(const char * a_string_base64);

#ifdef __cplusplus
}
#endif

#endif
