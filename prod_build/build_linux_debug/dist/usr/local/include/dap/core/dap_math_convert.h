#pragma once
#include "dap_math_ops.h"

/*
 * Forward declarations
 */
#define DATOSHI_DEGREE 18
#define DATOSHI_POW 39
#define DATOSHI_POW256 (DATOSHI_POW * 2)
#define DAP_CHAIN$SZ_MAX128DEC DATOSHI_POW                                          /* "340282366920938463463374607431768211455" */
#define DAP_CHAIN$SZ_MAX256DEC DATOSHI_POW256                                       /* 2 ^ 256 = 1.15792089237316195423570985008687907853269984665640564039457584007913129639935e77*/
#define DAP_SZ_MAX256SCINOT (DATOSHI_POW256 + 5)
#define DATOSHI_MULT UINT64_C(1000000000000000000)

#ifdef __cplusplus
extern "C" {
#endif

uint256_t dap_uint256_decimal_from_uint64(uint64_t a_uninteger);

/**
 * @brief dap_uint256_scan_uinteger
 * Converts a string value to uint256_t. The string value must be an unsigned integer.
 * @param a_str_integer char*
 * @return uint256_t
 */
uint256_t dap_uint256_scan_uninteger(const char *a_str_uninteger);
/*
 * @breif dap_uint256_scan_decimal
 *
 * Convert a text representation of the coins amount in to
 * the binary uint256 value .
 *      Coins string can be in form:
 *          - "123.00456"
 *
 * @param a_str_decimal A text string in format
 *
 * @return uint256_t
 */
uint256_t dap_uint256_scan_decimal(const char *a_str_decimal);

const char *dap_uint256_to_char(uint256_t a_uint256, const char **a_frac);

/**
 * @brief dap_uint256_uninteger_to_char
 * Convert a uint256_t value to a string value. Uint256_t is treated as an unsigned integer value.
 * @param a_uint256 unsigned integer value
 * @return char* String representation of the uint256_t value.
 */
char *dap_uint256_uninteger_to_char(uint256_t a_uninteger);
/**
 * @brief dap_uint256_decimal_to_char
 *
 * Converts a value from uint256_t to a string. The uint256_t value is treated as a fixed-point value.
 *
 * @param a_uint256
 * @return char*
 */
char *dap_uint256_decimal_to_char(uint256_t a_decimal);

/**
 * @brief dap_uint256_decimal_to_round_char
 *
 * Converts a value from uint256_t to a string. The uint256_t value is treated as a fixed-point value.
 * Rounds value to a_digits_after_point position after point.
 *
 * @param a_uint256
 * @return char*
 */
const char *dap_uint256_decimal_to_round_char(uint256_t a_uint256, uint8_t a_digits_after_point, bool is_round);

/**
 * @brief dap_uint256_char_to_round_char
 *
 * Converts a decimal string to a string with rounding to a_digits_after_point. The uint256_t value is treated as a fixed-point value.
 *
 * @param a_uint256
 * @return char*
 */
const char *dap_uint256_char_to_round_char(char* a_str_decimal, uint8_t a_round_position, bool is_round);

int dap_id_uint64_parse(const char *a_id_str, uint64_t *a_id);
uint64_t dap_uint128_to_uint64(uint128_t a_from);
uint64_t dap_uint256_to_uint64(uint256_t a_from);
uint128_t dap_uint256_to_uint128(uint256_t a_from);
char *dap_uint128_uninteger_to_char(uint128_t a_uninteger);
char *dap_uint128_decimal_to_char(uint128_t a_decimal);
uint128_t dap_uint128_scan_uninteger(const char *a_str_uninteger);
uint128_t dap_uint128_scan_decimal(const char *a_str_decimal);
double dap_uint256_decimal_to_double(uint256_t a_decimal);

#ifdef __cplusplus
}
#endif
