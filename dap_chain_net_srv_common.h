#pragma once
#include <stdint.h>
#include "dap_common.h"
#include "dap_math_ops.h"

#define DAP_CHAIN_NET_SRV_UID_SIZE 16
typedef union{
    uint8_t raw[DAP_CHAIN_NET_SRV_UID_SIZE];
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    uint64_t raw_ui64[1];
#elif DAP_CHAIN_NET_SRV_UID_SIZE == 16
    uint64_t raw_ui64[2];
    dap_uint128_t raw_ui128[1];
#endif
}  dap_chain_net_srv_uid_t;
