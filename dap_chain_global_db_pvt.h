#pragma once

#include <stdint.h>
#include "dap_common.h"
#include "ldb.h"

typedef struct dap_store_obj {
    char *section;
    char *group;
    char *key;
    uint8_t type;
    char *value;
}DAP_ALIGN_PACKED dap_store_obj_t, *pdap_store_obj_t;

typedef struct dap_store_obj_pkt {
    /*uint8_t type;
     uint8_t sec_size;
     uint8_t grp_size;
     uint8_t name_size;*/
    size_t data_size;
    uint8_t data[];
}__attribute__((packed)) dap_store_obj_pkt_t;

int dap_db_init(const char*);
void dap_db_deinit(void);

int dap_db_add(pdap_store_obj_t a_store_obj, int a_store_count);
int dap_db_delete(pdap_store_obj_t a_store_obj, int a_store_count);

pdap_store_obj_t dap_db_read_data(const char *a_query, int *a_count, const char *a_group);
pdap_store_obj_t dap_db_read_file_data(const char *a_path, const char *a_group); // state of emergency only, if LDB database is inaccessible
dap_store_obj_pkt_t *dap_store_packet_single(pdap_store_obj_t a_store_obj);
dap_store_obj_pkt_t *dap_store_packet_multiple(pdap_store_obj_t a_store_obj, int a_store_obj_count);
dap_store_obj_t *dap_store_unpacket(dap_store_obj_pkt_t *a_pkt, int *a_store_obj_count);

void dab_db_free_pdap_store_obj_t(pdap_store_obj_t a_store_data, int a_count);

