/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

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

#ifndef _DAP_CHAIN_H_
#define _DAP_CHAIN_H_

#include "dap_chain_block.h"

typedef struct dap_chain{
    dap_chain_block_t * mapped_block_first; // Mapped area start
    dap_chain_block_t * mapped_block_last; // Last block in mapped area
    uint64_t blocks_count;

    void * _internal;
    void * _inhertor;
} dap_chain_t;

dap_chain_t * dap_chain_open(const char * a_file_name);

void dap_chain_remap(dap_chain_t * a_chain, size_t a_offset);
void dap_chain_save(dap_chain_t * a_chain);

void dap_chain_close(dap_chain_t * a_chain);

#endif
