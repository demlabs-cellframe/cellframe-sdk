#ifndef __TABLES_H
#define __TABLES_H

#include <stdint.h>

/* Get access to internal tables for Gaussian sampling.
 *
 *  BLISS I:
 *  sigma = 215, ell = 21, precision = 64, 128
 *
 *  BLISS III:
 *  sigma = 250, ell = 21, precision = 64, 128
 *
 *  BLISS IV:
 *  sigma = 271, ell = 22, precision = 64, 128 */

/* Crufty error checking for now
 * - get the table for the given parameters
 * - return NULL if we don't have the table  */
extern const uint8_t* get_table(uint32_t sigma, uint32_t ell, uint32_t precision);

/* Get the k_sigma/k_sigma_bits */
extern uint16_t get_k_sigma(uint32_t sigma, uint32_t precision);
extern uint16_t get_k_sigma_bits(uint32_t sigma, uint32_t precision);

#endif
