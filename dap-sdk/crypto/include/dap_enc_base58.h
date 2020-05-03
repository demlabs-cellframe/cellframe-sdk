/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame https://cellframe.net
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

#ifndef _DAP_ENC_BASE58_H_
#define _DAP_ENC_BASE58_H_
#include <stddef.h>
#include <stdint.h>
#include "dap_enc_key.h"
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Calculates encode size from input size
 */
#define DAP_ENC_BASE58_ENCODE_SIZE(a_in_size) ( (size_t) ((137 * a_in_size / 100)+2))
#define DAP_ENC_BASE58_DECODE_SIZE(a_in_size) ( (size_t) ( 2 * a_in_size   +1) )

size_t dap_enc_base58_encode(const void * a_in, size_t a_in_size, char * a_out);
size_t dap_enc_base58_decode(const char * a_in, void * a_out);

#ifdef __cplusplus
}
#endif

#endif
