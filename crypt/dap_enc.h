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

#ifndef _DAP_ENC_H_
#define _DAP_ENC_H_
#include <stddef.h>
#include <stdbool.h>

#include "dap_enc_key.h"

int dap_enc_init();

size_t dap_enc_code(struct dap_enc_key * key, const void * buf, const size_t buf_size, void * buf_out,
                    dap_enc_data_type_t data_type_out);
size_t dap_enc_decode(struct dap_enc_key * key, const void * buf, const size_t buf_size, void * buf_out,
                      dap_enc_data_type_t data_type_in);


#endif
