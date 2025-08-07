#include "dap_test.h"
#include "dap_chain_cell.h"
#include "dap_chain.h"
#include "dap_chain_datum.h"
#include <json-c/json.h>
static json_object* local_datum_to_json(dap_chain_datum_t* d){
    json_object *o=json_object_new_object();
    dap_chain_net_id_t net_id={.uint64=0};
    dap_chain_datum_dump_json(NULL,o,d,"hex",net_id,false,2);
    return o;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#define REAL_CELL_PATH "/opt/cellframe-node/var/lib/network/riemann/main/0.dchaincell"
#define CELL_HDR_SIZE 40 // size of dap_chain_cell_file_header_t (bytes)
#define MAX_TEST_ATOM_SIZE (2<<20) // 2 MB cap
#define DATUM_TYPE_TX 3

static dap_chain_t* s_fake_chain(bool a_mapped)
{
    dap_chain_t *chain = calloc(1, sizeof(dap_chain_t));
    chain->is_mapped = a_mapped;
    return chain;
}

void dap_chain_cell_realfile_random_test(void)
{
    FILE *f = fopen(REAL_CELL_PATH, "rb");
    if(!f){
        dap_fail("cannot open real chain file");
        return;
    }
    // skip header
    fseek(f, CELL_HDR_SIZE, SEEK_SET);
    size_t atom_count = 0;
    off_t offsets[1024]; uint64_t sizes[1024]; // store up to 1024 offsets
    while(1){
        off_t off = ftello(f);
        uint64_t sz;
        if(fread(&sz, sizeof(sz), 1, f)!=1) break;
        if(sz==0) break;
        if(sz<=MAX_TEST_ATOM_SIZE && atom_count<1024){
            offsets[atom_count]=off;
            sizes[atom_count]=sz;
            atom_count++;}
        fseek(f, sz, SEEK_CUR);
    }
    dap_assert(atom_count>0, "file has atoms");

    srand((unsigned)time(NULL));
    size_t wanted_json = atom_count < 3 ? atom_count : 3;

    // prepare cell struct once
    dap_chain_cell_t cell = {0};
    cell.file_storage = f;
    cell.file_storage_type = 0; // RAW
    dap_chain_t *chain = s_fake_chain(true);
    cell.chain = chain;

    size_t printed=0;
    for(size_t idx=0; idx<atom_count && printed<wanted_json; idx++){    

        off_t target_off = offsets[idx];
        uint64_t sz = sizes[idx];

        dap_chain_atom_ptr_t ptr=NULL; uint64_t outsz=0;
        int rc = dap_chain_cell_atom_read_at_offset(&cell, target_off, &ptr, &outsz);
        if(rc!=0) continue;
        uint8_t *p8 = (uint8_t*)ptr;
        uint16_t type_id = p8[1] | (p8[2]<<8);
        if(type_id != 0x0100 && type_id != 0x0300) {
            if(!cell.chain->is_mapped) free((void*)ptr);
            continue; // not a TX
        }
        // manual read for comparison
        fseek(f, target_off + sizeof(uint64_t), SEEK_SET);
        void *buf = malloc(sz);
        if(!buf){ if(!cell.chain->is_mapped) free((void*)ptr); continue; }
        fread(buf, sz,1,f);

        char msg[64]; snprintf(msg, sizeof(msg), "tx %zu rc", printed);
        dap_assert(rc==0, msg);
        snprintf(msg, sizeof(msg), "idx %zu size", idx);
        dap_assert(outsz==sz, msg);
        snprintf(msg, sizeof(msg), "idx %zu cmp", idx);
        dap_assert(memcmp(ptr, buf, (sz<32?sz:32))==0, msg);

        {
            json_object *j = local_datum_to_json((dap_chain_datum_t*)ptr);
            if(j){
                printf("JSON %zu:\n%s\n", printed, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PRETTY));
                json_object_put(j);
                printed++;
            } else {
            printf("Atom size %lu first16:", (unsigned long)sz);
            for(int b=0;b<16 && (uint64_t)b<sz;b++)
                printf(" %02X", ((uint8_t*)ptr)[b]);
            puts("");
            }
        }
        if(!cell.chain->is_mapped)
            free((void*)ptr);
        free(buf);
    }

    fclose(f);
    free(chain);
}

void dap_chain_cell_realfile_tests_run(void){
    dap_print_module_name("chain_cell_realfile");
    dap_chain_cell_realfile_random_test();
}

