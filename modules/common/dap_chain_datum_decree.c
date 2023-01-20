/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.

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

#include <memory.h>
#include <assert.h>
#include "dap_common.h"
#include "dap_sign.h"
#include "dap_chain_datum_decree.h"

#define LOG_TAG "dap_chain_datum_decree"



int dap_chain_datum_decree_vify_sign(dap_chain_datum_decree_t *decree)
{
    int ret = -1;
    uint32_t decree_tsd_pos = 0, decree_tsd_size = decree->header.decree_tsd_size;
    while(decree_tsd_pos < decree_tsd_size){
        uint8_t *item = decree->tsd_sections + decree_tsd_pos;
//        size_t l_decree_tsd_size =
    }
}
