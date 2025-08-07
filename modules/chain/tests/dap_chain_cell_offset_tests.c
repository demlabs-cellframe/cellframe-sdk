#include "dap_test.h"
#include "dap_chain_cell.h"
#include "dap_chain_common.h"
#include "dap_chain.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#ifndef DAP_MAPPED_VOLUME_LIMIT
#define DAP_MAPPED_VOLUME_LIMIT (1UL << 28) // 256 MB default if not available
#endif

/* helper that prepares minimal chain structure */
static dap_chain_t* s_prepare_chain(const char *a_dir, bool a_mapped)
{
    dap_chain_t *l_chain = calloc(1, sizeof(dap_chain_t));
    l_chain->is_mapped = a_mapped;
    dap_chain_pvt_t *priv = calloc(1, sizeof(dap_chain_pvt_t));
    priv->file_storage_dir = strdup(a_dir);
    l_chain->_pvt = priv;
    pthread_rwlock_init(&l_chain->cell_rwlock, NULL);
    return l_chain;
}

static void s_cleanup_chain(dap_chain_t *a_chain)
{
    if (!a_chain) return;
    free(DAP_CHAIN_PVT(a_chain)->file_storage_dir);
    free(a_chain->_pvt);
    pthread_rwlock_destroy(&a_chain->cell_rwlock);
    free(a_chain);
}

void dap_chain_cell_offset_test(void){
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/tmp/offset_test_%u", (unsigned)getpid());
    mkdir(tmp, 0700);
    dap_chain_t *l_chain = s_prepare_chain(tmp, true);

    dap_chain_cell_id_t cell_id = { .uint64 = 0 };
    dap_chain_cell_t *cell = dap_chain_cell_create_fill(l_chain, cell_id);

    const char *msg = "hello_atom";
    size_t msg_size = strlen(msg)+1;
    off_t off_before = ftello(cell->file_storage);
    dap_chain_cell_file_append(cell, msg, msg_size);

    dap_chain_atom_ptr_t atom_ptr = NULL;
    uint64_t atom_size = 0;
    int rc = dap_chain_cell_atom_read_at_offset(cell, off_before, &atom_ptr, &atom_size);

    dap_assert(rc == 0, "read at offset returns rc==0");
    dap_assert(atom_size == msg_size, "atom size matches");
    dap_assert(memcmp(atom_ptr, msg, msg_size)==0, "atom data matches");

    dap_chain_cell_delete(cell);
    s_cleanup_chain(l_chain);
    rmdir(tmp);
}

/* Bigger test crossing multiple mapped volumes */
void dap_chain_cell_offset_big_test(void)
{
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/tmp/offset_big_%u", (unsigned)getpid());
    mkdir(tmp, 0700);
    dap_chain_t *l_chain = s_prepare_chain(tmp, true);

    dap_chain_cell_id_t cell_id = { .uint64 = 0 };
    dap_chain_cell_t *cell = dap_chain_cell_create_fill(l_chain, cell_id);

    const size_t ATOM_SIZE = 4 * 1024 * 1024; // 4 MB
    const size_t TOTAL_VOLUME = (size_t)DAP_MAPPED_VOLUME_LIMIT * 3 + (1<<20); // 3 volumes + 1 MB
    size_t atoms_needed = TOTAL_VOLUME / ATOM_SIZE + 1;

    byte_t *buffer = malloc(ATOM_SIZE);
    for(size_t i=0;i<ATOM_SIZE;i++)
        buffer[i] = (byte_t)(i & 0xFF);

    // record offsets & hashes for a subset of atoms
    const size_t REC_CNT = 30;
    off_t rec_offsets[REC_CNT];
    size_t rec_idx=0;

    for(size_t a=0;a<atoms_needed;a++){
        off_t off = ftello(cell->file_storage);
        dap_chain_cell_file_append(cell, buffer, ATOM_SIZE);
        if (rec_idx < REC_CNT && (a % (atoms_needed/REC_CNT+1) == 0))
            rec_offsets[rec_idx++] = off;
    }

    // validate recorded atoms
    for(size_t i=0;i<rec_idx;i++){
        dap_chain_atom_ptr_t ptr=NULL; uint64_t sz=0;
        int r = dap_chain_cell_atom_read_at_offset(cell, rec_offsets[i], &ptr, &sz);
        dap_assert(r==0, "big read rc==0");
        dap_assert(sz==ATOM_SIZE, "big atom size matches");
        dap_assert(memcmp(ptr, buffer, 32)==0, "first bytes match");
    }

    free(buffer);
    dap_chain_cell_delete(cell);
    s_cleanup_chain(l_chain);
    rmdir(tmp);
}

void dap_chain_cell_offset_tests_run(void){
    dap_print_module_name("chain_cell_offset");
    dap_chain_cell_offset_test();
    dap_chain_cell_offset_big_test();
}
