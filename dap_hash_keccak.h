#pragma once
#include "keccak.h"


inline void dap_hash_keccak(const void * a_in, size_t a_in_size, void * a_out, size_t a_out_size)
{
    keccak((const uint8_t*) a_in,a_in_size, (uint8_t *) a_out,  a_out_size );
}


