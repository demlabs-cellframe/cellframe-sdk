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
#include "dap_math_ops.h"
#define LOG_TAG "dap_math_ops"

/**
 * @brief dap_chain_balance_substract
 * @param a
 * @param b
 * @return
 */
uint128_t dap_uint128_substract(uint128_t a, uint128_t b)
{
#ifdef DAP_GLOBAL_IS_INT128
    if (a < b) {
        log_it(L_WARNING, "Substract result overflow");
        return 0;
    }
    return a - b;
#else
    uint128_t l_ret = {};
    if (a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo)) {
        log_it(L_WARNING, "Substract result overflow");
        return l_ret;
    }
    l_ret.hi = a.hi - b.hi;
    l_ret.lo = a.lo - b.lo;
    if (a.lo < b.lo)
        l_ret.hi--;
    return l_ret;
#endif
}

/**
 * @brief dap_chain_balance_add
 * @param a
 * @param b
 * @return
 */
uint128_t dap_uint128_add(uint128_t a, uint128_t b)
{
#ifdef DAP_GLOBAL_IS_INT128
    uint128_t l_ret = a + b;
    if (l_ret < a || l_ret < b) {
        log_it(L_WARNING, "Sum result overflow");
        return 0;
    }
#else
    uint128_t l_ret = {};
    l_ret.hi = a.hi + b.hi;
    l_ret.lo = a.lo + b.lo;
    if (l_ret.lo < a.lo || l_ret.lo < b.lo)
        l_ret.hi++;
    if (l_ret.hi < a.hi || l_ret.hi < b.hi) {
        log_it(L_WARNING, "Sum result overflow");
        uint128_t l_nul = {};
        return l_nul;
    }
#endif
    return l_ret;
}

/**
 * @brief dap_uint128_check_equal
 * @param a
 * @param b
 * @return
 */
bool dap_uint128_check_equal(uint128_t a, uint128_t b)
{
#ifdef DAP_GLOBAL_IS_INT128
    return a == b;
#else
    return a.hi==b.hi && a.lo==b.lo;
#endif

}
