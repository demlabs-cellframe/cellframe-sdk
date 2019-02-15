/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

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

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include "dap_hash.h"
#include "rand/dap_rand.h"
#include "dap_chain_net.h"
#include "dap_chain_node.h"

#define LOG_TAG "chain_node"

/**
 * Generate node address by shard id
 */
dap_chain_node_addr_t* dap_chain_node_gen_addr(dap_chain_shard_id_t *shard_id)
{
    if(!shard_id)
        return NULL;
    dap_chain_node_addr_t *a_addr = DAP_NEW_Z(dap_chain_node_addr_t);
    dap_chain_hash_t a_hash;
    dap_hash(shard_id, sizeof(dap_chain_shard_id_t), a_hash.raw, sizeof(a_hash.raw), DAP_HASH_TYPE_KECCAK);
    // first 4 bytes is last 4 bytes of shard id hash
    memcpy(a_addr->raw, a_hash.raw + sizeof(a_hash.raw) - sizeof(uint64_t) / 2, sizeof(uint64_t) / 2);
    // last 4 bytes is random
    randombytes(a_addr->raw + sizeof(uint64_t) / 2, sizeof(uint64_t) / 2);
    // for LITTLE_ENDIAN (Intel), do nothing, otherwise swap bytes
    a_addr->uint64 = le64toh(a_addr->uint64); // a_addr->raw the same a_addr->uint64
    return a_addr;
}

/**
 * Check the validity of the node address by shard id
 */
bool dap_chain_node_check_addr(dap_chain_node_addr_t *addr, dap_chain_shard_id_t *shard_id)
{
    bool ret = false;
    if(!addr || !shard_id)
        return ret;
    // generate new address by shard_id
    dap_chain_node_addr_t *tmp_addr = dap_chain_node_gen_addr(shard_id);
    if(tmp_addr) {

        if((uint32_t) addr->uint64 == (uint32_t) tmp_addr->uint64)
            ret = true;
        DAP_DELETE(tmp_addr);
    }
    return ret;
}

/**
 * Convert binary data to binhex encoded data.
 *
 * out output buffer, must be twice the number of bytes to encode.
 * len is the size of the data in the in[] buffer to encode.
 * return the number of bytes encoded, or -1 on error.
 */
int bin2hex(char *out, const unsigned char *in, int len)
{
    int ct = len;
    static char hex[] = "0123456789ABCDEF";
    if(!in || !out || len < 0)
        return -1;
    // hexadecimal lookup table
    while(ct-- > 0)
    {
        *out++ = hex[*in >> 4];
        *out++ = hex[*in++ & 0x0F];
    }
    return len;
}

/**
 * Convert binhex encoded data to binary data
 *
 * len is the size of the data in the in[] buffer to decode, and must be even.
 * out outputbuffer must be at least half of "len" in size.
 * The buffers in[] and out[] can be the same to allow in-place decoding.
 * return the number of bytes encoded, or -1 on error.
 */
int hex2bin(char *out, const unsigned char *in, int len)
{
    // '0'-'9' = 0x30-0x39
    // 'a'-'f' = 0x61-0x66
    // 'A'-'F' = 0x41-0x46
    int ct = len;
    if(!in || !out || len < 0 || (len & 1))
        return -1;
    while(ct > 0)
    {
        char ch1 = ((*in >= 'a') ? (*in++ - 'a' + 10) : ((*in >= 'A') ? (*in++ - 'A' + 10) : (*in++ - '0'))) << 4;
        char ch2 = ((*in >= 'a') ? (*in++ - 'a' + 10) : ((*in >= 'A') ? (*in++ - 'A' + 10) : (*in++ - '0'))); // ((*in >= 'A') ? (*in++ - 'A' + 10) : (*in++ - '0'));
        *out++ = ch1 + ch2;
        ct -= 2;
    }
    return len;
}

/**
 * Calculate size of struct dap_chain_node_info_t
 */
size_t dap_chain_node_info_get_size(dap_chain_node_info_t *node_info)
{
    if(!node_info)
        return 0;
    return (sizeof(dap_chain_node_info_t) + node_info->hdr.links_number * sizeof(dap_chain_node_addr_t));
}

/**
 * Serialize dap_chain_node_info_t
 * size[out] - length of output string
 * return data or NULL if error
 */
uint8_t* dap_chain_node_info_serialize(dap_chain_node_info_t *node_info, size_t *size)
{
    if(!node_info)
        return NULL;
    size_t node_info_size = dap_chain_node_info_get_size(node_info);
    size_t node_info_str_size = 2 * node_info_size + 1;
    uint8_t *node_info_str = DAP_NEW_Z_SIZE(uint8_t, node_info_str_size);
    if(bin2hex(node_info_str, (const unsigned char *) node_info, node_info_size) == -1) {
        DAP_DELETE(node_info_str);
        return NULL;
    }

    if(size)
        *size = node_info_str_size;
    return node_info_str;
}

/**
 * Deserialize dap_chain_node_info_t
 * size[in] - length of input string
 * return data or NULL if error
 */
dap_chain_node_info_t* dap_chain_node_info_deserialize(uint8_t *node_info_str, size_t size)
{
    if(!node_info_str)
        return NULL;
    dap_chain_node_info_t *node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t, (size / 2 + 1));
    if(hex2bin((char*) node_info, (const unsigned char *) node_info_str, size) == -1 ||
            (size / 2) != dap_chain_node_info_get_size(node_info)) {
        log_it(L_ERROR, "node_info_deserialize - bad node_info size (%ld!=%ld)",
                size / 2, dap_chain_node_info_get_size(node_info));
        DAP_DELETE(node_info);
        return NULL;
    }
    return node_info;
}

