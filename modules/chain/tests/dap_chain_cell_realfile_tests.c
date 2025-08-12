#include "dap_test.h"
#include "dap_chain_cell.h"
#include "dap_chain.h"
#include "dap_chain_datum.h"
#include "dap_chain_cell.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_block.h"
#include "dap_config.h"
#include "dap_chain_cs_dag_event.h"
#include "dap_chain_block.h"
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
#define CELL_HDR_SIZE 40 // fallback, will be auto-detected below
#define MAX_TEST_ATOM_SIZE (2<<20) // 2 MB cap
#define DATUM_TYPE_TX 3

static dap_chain_t* s_fake_chain(bool a_mapped)
{
    dap_chain_t *chain = calloc(1, sizeof(dap_chain_t));
    chain->is_mapped = a_mapped;
    return chain;
}

static off_t s_detect_first_atom_offset(FILE *f)
{
    // Try to detect header size by validating first plausible atom size
    off_t file_size;
    if (fseeko(f, 0, SEEK_END) != 0) return CELL_HDR_SIZE;
    file_size = ftello(f);
    if (file_size < 64) return CELL_HDR_SIZE;
    // Probe offsets from 32 to 128 with 8-byte alignment
    for (off_t off = 32; off <= 128; off += 8) {
        if (fseeko(f, off, SEEK_SET) != 0) break;
        uint64_t sz = 0;
        if (fread(&sz, sizeof(sz), 1, f) != 1) break;
        if (sz > 0 && sz < (uint64_t)(file_size - off - 8)) {
            // plausible first atom
            return off;
        }
    }
    return CELL_HDR_SIZE;
}

static bool s_try_open_cell(const char *path, FILE **out_f, off_t *out_data_off, uint8_t *out_type)
{
    *out_f = fopen(path, "rb");
    if(!*out_f) return false;
    // probe header
    uint8_t hdr_buf[16] = {0};
    fseeko(*out_f, 0, SEEK_SET);
    if (fread(hdr_buf, 1, sizeof(hdr_buf), *out_f) != sizeof(hdr_buf)) {
        fclose(*out_f); *out_f=NULL; return false;
    }
    uint64_t sig=0; memcpy(&sig, hdr_buf, sizeof(uint64_t));
    uint32_t ver=0; memcpy(&ver, hdr_buf+8, sizeof(uint32_t));
    uint8_t type = hdr_buf[12];
    if (sig != 0xFA340BEF153EBA48ULL || ver < 1) { fclose(*out_f); *out_f=NULL; return false; }
    *out_type = type;
    *out_data_off = s_detect_first_atom_offset(*out_f);
    fseeko(*out_f, *out_data_off, SEEK_SET);
    return true;
}

static FILE* s_find_first_cell_with_atoms(off_t *out_data_off, uint8_t *out_type, char *chosen_path, size_t chosen_path_size)
{
    const char *env_path = getenv("REAL_CELL_PATH");
    if (env_path) {
        FILE *f=NULL; off_t d_off=0; uint8_t t=0;
        if (s_try_open_cell(env_path, &f, &d_off, &t)) {
            snprintf(chosen_path, chosen_path_size, "%s", env_path);
            *out_data_off = d_off; *out_type = t; return f;
        }
    }
    // fallback scan: try 0..255 in default directory
    for (int i=0; i<256; i++) {
        char path[256];
        snprintf(path, sizeof(path), "/opt/cellframe-node/var/lib/network/riemann/main/%d.dchaincell", i);
        FILE *f=NULL; off_t d_off=0; uint8_t t=0;
        if (!s_try_open_cell(path, &f, &d_off, &t)) continue;
        // check if there is at least one plausible atom
        fseeko(f, d_off, SEEK_SET);
        uint64_t sz=0; if (fread(&sz, sizeof(sz), 1, f) != 1) { fclose(f); continue; }
        off_t file_size = !fseeko(f, 0, SEEK_END) ? ftello(f) : -1;
        if (file_size > 0 && sz > 0 && (off_t)(d_off + 8 + sz) <= file_size) {
            snprintf(chosen_path, chosen_path_size, "%s", path);
            *out_data_off = d_off; *out_type = t; fseeko(f, d_off, SEEK_SET); return f;
        }
        fclose(f);
    }
    return NULL;
}

void dap_chain_cell_realfile_random_test(void)
{
    char used_path[256] = {0};
    off_t data_off = 0; uint8_t hdr_type = 0;
    FILE *f = s_find_first_cell_with_atoms(&data_off, &hdr_type, used_path, sizeof(used_path));
    if(!f){ dap_fail("no suitable .dchaincell found (set REAL_CELL_PATH env or populate chain files)" ); return; }
    // print selected file info
    printf("Using cell: %s\n", used_path[0]?used_path:REAL_CELL_PATH);
    // restore file position to data offset for atom scan
    fseeko(f, data_off, SEEK_SET);
    // Streaming scan: iterate all atoms sequentially without size cap
    size_t atom_count_total = 0;
    printf("Detected header size guess: %ld bytes\n", (long)data_off);

    srand((unsigned)time(NULL));
    // Limit number of JSON outputs we print in this run
    size_t wanted_json = 3;

    // prepare cell struct once
    dap_chain_cell_t cell = {0};
    cell.file_storage = f;
    cell.file_storage_type = hdr_type; // respect on-disk type
    dap_chain_t *chain = s_fake_chain(true);
    cell.chain = chain;

    size_t printed=0; size_t idx=0;
    for (off_t target_off = data_off; printed < wanted_json; ++idx) {
        // read next size from file stream
        fseeko(f, target_off, SEEK_SET);
        uint64_t sz = 0;
        if (fread(&sz, sizeof(sz), 1, f) != 1) break;
        if (sz == 0) break;
        atom_count_total++;

        dap_chain_atom_ptr_t ptr=NULL; uint64_t outsz=0;
        int rc = dap_chain_cell_atom_read_at_offset(&cell, target_off, &ptr, &outsz);
        if (hdr_type == 1) {
            dap_assert(rc == -4, "compressed chain: read_at_offset must return -4");
            // advance to next atom
            target_off += (off_t)(sizeof(uint64_t) + sz);
            continue;
        }
        if(rc!=0) { target_off += (off_t)(sizeof(uint64_t) + sz); continue; }
        // Atom may be:
        // 1) DAG event containing a datum
        // 2) Block containing a list of datums
        // 3) Raw single datum
        const void *raw_atom_ptr = ptr; // keep raw atom for bytewise comparison
        bool tx_found_in_atom = false;

        // Try DAG event first
        if (!tx_found_in_atom) {
            dap_chain_cs_dag_event_t *ev = (dap_chain_cs_dag_event_t*)ptr;
            // Basic plausibility checks before treating atom as DAG event
            if (outsz >= sizeof(ev->header) && ev->header.hash_count < 4096 && ev->header.signs_count < 4096) {
                printf("DAG event candidate: idx=%zu off=%ld sz=%lu ver=%u hash_count=%u signs_count=%u\n",
                       idx, (long)target_off, (unsigned long)outsz,
                       (unsigned)ev->header.version, (unsigned)ev->header.hash_count, (unsigned)ev->header.signs_count);
            }
            dap_chain_datum_t *datum = dap_chain_cs_dag_event_get_datum(ev, (size_t)outsz);
            if (datum) {
                uint16_t type_id = datum->header.type_id;
                if (type_id == DAP_CHAIN_DATUM_TX || type_id == DAP_CHAIN_DATUM_TX_REQUEST) {
                    // Dump parsed datum to JSON for visibility
                    json_object *j = local_datum_to_json(datum);
                    if (j) {
                        printf("DAG event: TX datum at atom #%zu (offset %ld)\n", idx, (long)target_off);
                        printf("JSON %zu:\n%s\n", printed, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PRETTY));
                        json_object_put(j);
                        printed++;
                        tx_found_in_atom = true;
                    }
                }
            }
        }

        // Try DAG round-item wrapping (contains embedded event)
        if (!tx_found_in_atom) {
            dap_chain_cs_dag_event_round_item_t *ri = (dap_chain_cs_dag_event_round_item_t*)ptr;
            if (outsz >= sizeof(*ri)) {
                size_t ri_size = sizeof(*ri) + ri->data_size;
                if (ri_size <= outsz && ri->data_size > 0 && ri->event_size > 0 && ri->event_size <= ri->data_size) {
                    dap_chain_cs_dag_event_t *ev = (dap_chain_cs_dag_event_t*)ri->event_n_signs;
                    printf("DAG round item: idx=%zu off=%ld sz=%lu ev_size=%u data_size=%u\n",
                           idx, (long)target_off, (unsigned long)outsz, (unsigned)ri->event_size, (unsigned)ri->data_size);
                    dap_chain_datum_t *datum = dap_chain_cs_dag_event_get_datum(ev, ri->event_size);
                    if (datum && (datum->header.type_id == DAP_CHAIN_DATUM_TX || datum->header.type_id == DAP_CHAIN_DATUM_TX_REQUEST)) {
                        json_object *j = local_datum_to_json(datum);
                        if (j) {
                            printf("DAG round: TX datum at atom #%zu (offset %ld)\n", idx, (long)target_off);
                            printf("JSON %zu:\n%s\n", printed, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PRETTY));
                            json_object_put(j);
                            printed++;
                            tx_found_in_atom = true;
                        }
                    }
                }
            }
        }

        // Try Block structure next (validate signature first)
        if (!tx_found_in_atom) {
            size_t datums_count = 0;
            dap_chain_block_t *blk = (dap_chain_block_t*)ptr;
            if (outsz >= sizeof(blk->hdr) && blk->hdr.signature == DAP_CHAIN_BLOCK_SIGNATURE) {
                printf("Block candidate: idx=%zu off=%ld sz=%lu sig=0x%08X ver=%d datums=%u\n",
                       idx, (long)target_off, (unsigned long)outsz,
                       (unsigned)blk->hdr.signature, (int)blk->hdr.version, (unsigned)blk->hdr.datum_count);
            }
            dap_chain_datum_t **datums = NULL;
            if (outsz >= sizeof(blk->hdr) && blk->hdr.signature == DAP_CHAIN_BLOCK_SIGNATURE) {
                datums = dap_chain_block_get_datums(blk, (size_t)outsz, &datums_count);
            }
            if (datums && datums_count > 0) {
                printf("Block atom #%zu: contains %zu datums\n", idx, datums_count);
                for (size_t di = 0; di < datums_count && printed < wanted_json; di++) {
                    dap_chain_datum_t *d = datums[di];
                    if (!d) continue;
                    uint16_t type_id = d->header.type_id;
                    if (type_id == DAP_CHAIN_DATUM_TX || type_id == DAP_CHAIN_DATUM_TX_REQUEST) {
                        json_object *j = local_datum_to_json(d);
                        if (j) {
                            printf("BLOCK: TX datum at atom #%zu, datum #%zu (offset %ld)\n", idx, di, (long)target_off);
                            printf("JSON %zu:\n%s\n", printed, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PRETTY));
                            json_object_put(j);
                            printed++;
                            tx_found_in_atom = true; // keep scanning only until wanted_json
                        }
                    }
                }
                DAP_DELETE(datums);
            }
        }

        // Fallback: treat as raw datum
        if (!tx_found_in_atom) {
            if (outsz >= sizeof(dap_chain_datum_t)) {
                dap_chain_datum_t *datum = (dap_chain_datum_t*)ptr;
                uint16_t type_id = datum->header.type_id;
                const char *type_str = dap_chain_datum_type_id_to_str(type_id);
                printf("RAW datum candidate at atom #%zu (offset %ld), type_id=0x%04X (%s), data_size=%u\n",
                       idx, (long)target_off, (unsigned)type_id, type_str, datum->header.data_size);
                if (type_id == DAP_CHAIN_DATUM_TX || type_id == DAP_CHAIN_DATUM_TX_REQUEST) {
                    json_object *j = local_datum_to_json(datum);
                    if (j) {
                        printf("RAW: TX datum at atom #%zu (offset %ld)\n", idx, (long)target_off);
                        printf("JSON %zu:\n%s\n", printed, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PRETTY));
                        json_object_put(j);
                        printed++;
                        tx_found_in_atom = true;
                    }
                }
            }
        }

            if (!tx_found_in_atom) {
                // Not a TX: print minimal debug info about the atom
                printf("Atom #%zu at offset %ld: no TX datum found (size %lu)\n", idx, (long)target_off, (unsigned long)sz);
            }
        // Manual read for comparison (ground truth)
        fseek(f, target_off + sizeof(uint64_t), SEEK_SET);
        void *buf = malloc(sz < (1<<22) ? sz : (1<<22)); // cap copy to 4MB for safety
        if(!buf){ if(!cell.chain->is_mapped) free((void*)ptr); target_off += (off_t)(sizeof(uint64_t) + sz); continue; }
        fread(buf, (sz < (1<<22) ? sz : (1<<22)),1,f);

        char msg[64]; snprintf(msg, sizeof(msg), "tx %zu rc", printed);
        dap_assert(rc==0, msg);
        snprintf(msg, sizeof(msg), "idx %zu size", idx);
        dap_assert(outsz==sz, msg);
        snprintf(msg, sizeof(msg), "idx %zu cmp", idx);
        dap_assert(memcmp(raw_atom_ptr, buf, (sz<32?sz:32))==0, msg);

        {
            // Validate pointer->offset mapping consistency in mapped mode
            off_t off_from_ptr = dap_chain_cell_atom_offset_get_by_ptr(&cell, raw_atom_ptr);
            if (cell.chain->is_mapped) {
                dap_assert(off_from_ptr == target_off, "offset computed from ptr equals expected offset");
            }
            // Note: JSON already printed above for DAG/BLOCK/RAW TX cases.
            // If not printed, provide a brief hex preview for troubleshooting.
            if (!tx_found_in_atom) {
                printf("Atom size %lu first16:", (unsigned long)sz);
                for(int b=0;b<16 && (uint64_t)b<sz;b++)
                    printf(" %02X", ((uint8_t*)ptr)[b]);
                puts("");
            }
        }
        if(!cell.chain->is_mapped)
            free((void*)ptr);
        free(buf);

        // advance to next atom
        target_off += (off_t)(sizeof(uint64_t) + sz);
    }
    printf("Total atoms scanned: %zu\n", atom_count_total);
    fclose(f);
    free(chain);
}

void dap_chain_cell_realfile_tests_run(void){
    dap_print_module_name("chain_cell_realfile");
    dap_chain_cell_realfile_random_test();
}

// Load real chain via consensus pipeline and dump first TXs
void dap_chain_cell_realfile_consensus_test(void)
{
    const char *net_name = "riemann";
    const char *chain_name = "main";
    const char *storage_dir = "/opt/cellframe-node/var/lib/network/riemann/main";

    // Initialize consensus modules
    dap_chain_cs_blocks_init();

    // Create chain with blocks consensus
    dap_chain_net_id_t net_id = {.uint64=1};
    dap_chain_id_t chain_id = {.uint64=1};
    dap_chain_t *chain = dap_chain_create(net_name, chain_name, net_id, chain_id);
    dap_config_t cfg = {};
    dap_chain_cs_create(chain, &cfg);

    // Point storage dir to real files
    DAP_CHAIN_PVT(chain)->file_storage_dir = dap_strdup(storage_dir);
    chain->is_mapped = false; // open read-only fallback (no write perms on system cells)

    // Open and load cell 0 in read-only mode without create_fill
    dap_chain_cell_t cell = {0};
    cell.id = (dap_chain_cell_id_t){.uint64=0};
    cell.chain = chain;
    cell.file_storage = fopen(REAL_CELL_PATH, "rb");
    if (!cell.file_storage) { dap_fail("cannot open chain cell 0!" ); return; }
    int rc = dap_chain_cell_load(chain, &cell);
    dap_assert(rc >= 0, "cell load rc");

    // Iterate atoms via consensus iterator and extract TX datums from blocks
    size_t printed = 0, want = 3;
    dap_chain_atom_iter_t *it = chain->callback_atom_iter_create(chain, (dap_chain_cell_id_t){.uint64=0}, NULL);
    size_t atom_size = 0;
    for (dap_chain_atom_ptr_t atom = chain->callback_atom_iter_get(it, DAP_CHAIN_ITER_OP_FIRST, &atom_size);
         atom && atom_size && printed < want;
         atom = chain->callback_atom_iter_get(it, DAP_CHAIN_ITER_OP_NEXT, &atom_size))
    {
        size_t datums_count = 0;
        dap_chain_datum_t **datums = chain->callback_atom_get_datums ? chain->callback_atom_get_datums(atom, atom_size, &datums_count) : NULL;
        if (!datums || !datums_count) continue;
        for (size_t i=0; i<datums_count && printed < want; ++i) {
            dap_chain_datum_t *d = datums[i]; if (!d) continue;
            if (d->header.type_id == DAP_CHAIN_DATUM_TX || d->header.type_id == DAP_CHAIN_DATUM_TX_REQUEST) {
                json_object *j = local_datum_to_json(d);
                if (j) {
                    printf("CONSENSUS JSON %zu:\n%s\n", printed, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PRETTY));
                    json_object_put(j);
                    ++printed;
                }
            }
        }
        DAP_DELETE(datums);
    }
    chain->callback_atom_iter_delete(it);

    if (printed == 0)
        dap_fail("no TX found via consensus iterator");
}

