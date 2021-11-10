/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2021
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <time.h>
#include <stdatomic.h>
#include "KeccakHash.h"
#include "SimpleFIPS202.h"
#include "dap_uuid.h"
#include "dap_rand.h"
#include "dap_math_ops.h"

#define LOG_TAG "dap_uuid"

atomic_uint_fast32_t s_global_counter32=0;
atomic_uint_fast16_t s_global_counter16=0;

/**
 * @brief dap_uuid_generate_ui64
 * @details Produce uint64 unique id
 * @return
 */
uint128_t dap_uuid_generate_uint128()
{
    uint32_t l_input[4] ={
        [0]=random_uint32_t(UINT32_MAX),
        [1]=time(NULL),
        [2]=s_global_counter32++,
        [3]=random_uint32_t(UINT32_MAX)
    };
    uint128_t l_output;
    SHAKE128((unsigned char *) &l_output,sizeof (l_output), (unsigned char*) &l_input,sizeof (l_input));
 //   uint64_t *l_output_u64 =(uint64_t*) &l_output;
   // log_it(L_DEBUG,"UUID generated 0x%016X%016X (0x%08X%08X%08X%08X",l_output_u64[0],l_output_u64[1],
   //         l_input[0],l_input[1],l_input[2],l_input[3]);
    return l_output;
}

/**
 * @brief dap_uuid_generate_uint64
 * @return
 */
uint64_t dap_uuid_generate_uint64()
{
    uint32_t l_ts = (uint32_t) time(NULL);
    uint16_t l_input[4] ={
        [0]=dap_random_uint16(),
        [1]= l_ts % UINT16_MAX,
        [2]= s_global_counter16++,
        [3]= dap_random_uint16()
    };
    uint64_t l_output;
    SHAKE128((unsigned char *) &l_output,sizeof (l_output), (unsigned char*) &l_input,sizeof (l_input));
   // log_it(L_DEBUG,"UUID generated 0x%016X%016X (0x%08X%08X%08X%08X",l_output_u64[0],l_output_u64[1],
   //         l_input[0],l_input[1],l_input[2],l_input[3]);
    return l_output;
}
