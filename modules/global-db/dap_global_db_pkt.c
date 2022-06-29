/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Demlabs Ltd.   https://demlabs.net
 * Copyright  (c) 2022
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

#include "dap_common.h"
#include "dap_global_db_pkt.h"
#include "dap_chain_global_db_driver.h"
#define LOG_TAG "dap_global_db_pkt"

/**
 * @brief Deserializes some objects from a packed structure into an array of objects.
 * @param pkt a pointer to the serialized packed structure
 * @param store_obj_count[out] a number of deserialized objects in the array
 * @return Returns a pointer to the first object in the array, if successful; otherwise NULL.
 */
dap_store_obj_t *dap_global_db_pkt_deserialize(const dap_global_db_pkt_t *a_pkt, size_t *a_store_obj_count)
{
    if(!a_pkt || a_pkt->data_size < sizeof(dap_global_db_pkt_t))
        return NULL;
    uint64_t l_offset = 0;
    uint32_t l_count = a_pkt->obj_count, l_cur_count;
    uint64_t l_size = l_count <= UINT16_MAX ? l_count * sizeof(struct dap_store_obj) : 0;
    dap_store_obj_t *l_store_obj = l_size? DAP_NEW_Z_SIZE(dap_store_obj_t, l_size) : NULL;
    if (!l_store_obj || !l_size) {
        log_it(L_ERROR, "Invalid size: can't allocate %"DAP_UINT64_FORMAT_U" bytes", l_size);
        DAP_DEL_Z(l_store_obj)
        return NULL;
    }
    for(l_cur_count = 0; l_cur_count < l_count; ++l_cur_count) {
        dap_store_obj_t *l_obj = l_store_obj + l_cur_count;
        uint16_t l_str_length;

        uint32_t l_type;
        if (l_offset+sizeof (uint32_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'type' field"); break;} // Check for buffer boundries
        memcpy(&l_type, a_pkt->data + l_offset, sizeof(uint32_t));
        l_obj->type = l_type;
        l_offset += sizeof(uint32_t);

        if (l_offset+sizeof (uint16_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'group_length' field"); break;} // Check for buffer boundries
        memcpy(&l_str_length, a_pkt->data + l_offset, sizeof(uint16_t));
        l_offset += sizeof(uint16_t);

        if (l_offset + l_str_length > a_pkt->data_size || !l_str_length) {log_it(L_ERROR, "Broken GDB element: can't read 'group' field"); break;} // Check for buffer boundries
        l_obj->group = DAP_NEW_Z_SIZE(char, l_str_length + 1);
        memcpy(l_obj->group, a_pkt->data + l_offset, l_str_length);
        l_offset += l_str_length;

        if (l_offset+sizeof (uint64_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'id' field");
                                                           DAP_DEL_Z(l_obj->group); break;} // Check for buffer boundries
        memcpy(&l_obj->id, a_pkt->data + l_offset, sizeof(uint64_t));
        l_offset += sizeof(uint64_t);

        if (l_offset+sizeof (uint64_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'timestamp' field");
                                                           DAP_DEL_Z(l_obj->group); break;} // Check for buffer boundries
        memcpy(&l_obj->timestamp, a_pkt->data + l_offset, sizeof(uint64_t));
        l_offset += sizeof(uint64_t);

        if (l_offset+sizeof (uint16_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'key_length' field");
                                                           DAP_DEL_Z(l_obj->group); break;} // Check for buffer boundries
        memcpy(&l_str_length, a_pkt->data + l_offset, sizeof(uint16_t));
        l_offset += sizeof(uint16_t);

        if (l_offset + l_str_length > a_pkt->data_size || !l_str_length) {log_it(L_ERROR, "Broken GDB element: can't read 'key' field: len %s",
                                                                                 l_str_length ? "OVER" : "NULL");
                                                                          DAP_DEL_Z(l_obj->group); break;} // Check for buffer boundries
        l_obj->key = DAP_NEW_Z_SIZE(char, l_str_length + 1);
        memcpy((char *)l_obj->key, a_pkt->data + l_offset, l_str_length);
        l_offset += l_str_length;

        if (l_offset+sizeof (uint64_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'value_length' field");
                                                           DAP_DEL_Z(l_obj->group); DAP_DEL_Z(l_obj->key); break;} // Check for buffer boundries
        memcpy(&l_obj->value_len, a_pkt->data + l_offset, sizeof(uint64_t));
        l_offset += sizeof(uint64_t);

        if (l_offset + l_obj->value_len > a_pkt->data_size || !l_obj->value_len) {log_it(L_ERROR, "Broken GDB element: can't read 'value' field");
                                                          DAP_DEL_Z(l_obj->group); DAP_DEL_Z(l_obj->key);break;} // Check for buffer boundries
        l_obj->value = DAP_NEW_Z_SIZE(uint8_t, l_obj->value_len);
        memcpy((char*)l_obj->value, a_pkt->data + l_offset, l_obj->value_len);
        l_offset += l_obj->value_len;
    }
    if (a_pkt->data_size != l_offset) {
        if (l_store_obj)
            dap_store_obj_free(l_store_obj, l_cur_count);
        return NULL;
    }
    // Return the number of completely filled dap_store_obj_t structures
    // because l_cur_count may be less than l_count due to too little memory
    if(a_store_obj_count)
        *a_store_obj_count = l_cur_count;
    return l_store_obj;
}

