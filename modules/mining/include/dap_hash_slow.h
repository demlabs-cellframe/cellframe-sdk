/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
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

#pragma once

#include "hash-ops.h"

#define DAP_HASH_SLOW_SIZE HASH_SIZE

/**
 * @brief dap_hash_slow
 * @param a_in
 * @param a_in_length
 * @param a_out Must be allocated with enought space
 */
static inline void dap_hash_slow(const void *a_in, size_t a_in_length, char * a_out)
{
    cn_slow_hash(a_in,a_in_length,a_out);
}

static inline size_t dap_hash_slow_size() { return DAP_HASH_SLOW_SIZE; }
//cn_slow_hash(data, length, reinterpret_cast<char *>(&hash));
