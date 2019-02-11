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

int dap_db_add_msg(struct ldb_message *);
int dap_db_merge(pdap_store_obj_t store_obj, int dap_store_size, const char *group);
int dap_db_delete(pdap_store_obj_t store_obj, int dap_store_size, const char *group);

pdap_store_obj_t dap_db_read_data(const char *query, int *count, const char *group);
pdap_store_obj_t dap_db_read_file_data(const char *path, const char *group); // state of emergency only, if LDB database is inaccessible
dap_store_obj_pkt_t *dap_store_packet_single(pdap_store_obj_t store_obj);
dap_store_obj_pkt_t *dap_store_packet_multiple(pdap_store_obj_t store_obj, int store_obj_count);
dap_store_obj_t *dap_store_unpacket(dap_store_obj_pkt_t *pkt, int *store_obj_count);

void dab_db_free_pdap_store_obj_t(pdap_store_obj_t store_data, int count);

