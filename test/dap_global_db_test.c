#include <time.h>
#include <unistd.h>
#include <stdatomic.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_events.h"
#include "dap_proc_thread.h"
#include "dap_proc_queue.h"
#include "dap_hash.h"

#include "dap_chain_global_db.h"
#include "dap_chain_global_db_driver.h"

#define LOG_TAG "dap_globaldb_test"

#define DB_FILE "./base.tmp"



static int s_test_create_db(const char *db_type, int mode)
{
int rc;
char    l_cmd[MAX_PATH];

    if( dap_dir_test(DB_FILE) ) {
        rmdir(DB_FILE);
        dap_snprintf(l_cmd, sizeof(l_cmd), "rm -rf %s", DB_FILE);
        if ( (rc = system(l_cmd)) )
             log_it(L_ERROR, "system(%s)->%d", l_cmd, rc);
    }
    else
        unlink(DB_FILE);

    if ( rc = dap_db_driver_init(db_type, DB_FILE, mode) )
        return  log_it(L_ERROR, "DB driver initialization, dap_db_driver_init(%s, %s)->%d", db_type, DB_FILE, rc), rc;


    return  log_it(L_NOTICE, "%s DB driver has been initialized in %s mode on the %s", db_type, mode ? "Async" : "Sync", DB_FILE),
            rc;
}

typedef struct __dap_test_record__ {
    dap_chain_hash_fast_t   csum;                                           /* CRC32 , cover <len> and <data> fields */
    unsigned    len;                                                        /* Length of the <data> field */
    char        data[];                                                     /* Place holder for data area */
} dap_db_test_record_t;

#define DAP_DB$SZ_DATA  8192
#define DAP_DB$SZ_KEY   64
#define DAP_DB$T_GROUP  "Group.Zero"


static  void    s_test_cb_end   (void *__unused_arg__, const void *arg)
{
int     *l_is_completed = (int *) arg;

    log_it(L_NOTICE, "Callback is called with arg: %p", arg);
    atomic_fetch_add(l_is_completed, 1);
}

static int s_test_write(int a_count, int a_mode)
{
dap_store_obj_t l_store_obj = {0};
int     l_value_len = 0, *l_pvalue, i, ret, l_key_nr;
atomic_int  l_is_completed = 0;
char    l_key[64] = {0}, l_value[sizeof(dap_db_test_record_t) + DAP_DB$SZ_DATA] = {0};
dap_db_test_record_t    *prec;
struct  timespec    now;

    log_it(L_NOTICE, "Start writing %d records ...", a_count);

                                                                            /* Fill static part of the <store_object> descriptor  */
    l_store_obj.type = DAP_DB$K_OPTYPE_ADD;                                 /* Do INSERT */


    l_store_obj.group = DAP_DB$T_GROUP;                                     /* "Table" name */
    l_store_obj.key = l_key;                                                /* Point <.key> to the buffer with the key of record */
    l_store_obj.value = (int8_t *) l_value;                                 /* Point <.value> to static buffer area */
    prec = (dap_db_test_record_t *) l_value;

    for (l_key_nr = 0; l_key_nr < a_count; l_key_nr++ )
        {

        if ( a_mode && (l_key_nr ==  (a_count - 1)) )                       /* Async mode ? Last request ?*/
        {
            l_store_obj.cb = s_test_cb_end;                                 /* Callback on request complete should be called */
            l_store_obj.cb_arg = &l_is_completed;
        }


        snprintf(l_key, sizeof(l_key) - 1, "KEY$%08x", l_key_nr);           /* Generate a key of record */

        clock_gettime(CLOCK_REALTIME, &now);                                /* Get and save record's timestamp */
        l_store_obj.timestamp = (now.tv_sec << 32) | ((uint32_t) (now.tv_nsec));


        prec->len = rand() % DAP_DB$SZ_DATA;                                /* Variable payload length */
        l_pvalue   = (int *) prec->data;

        for (int  i = prec->len / sizeof(int); i--; l_pvalue++)             /* Fill record's payload with random data */
            *l_pvalue = rand();

        sprintf(prec->data, "DATA$%08x", l_key_nr);                         /* Just for fun ... */
        l_value_len = prec->len + sizeof(dap_db_test_record_t);

        l_store_obj.value_len = l_value_len;
        assert(l_store_obj.value_len < sizeof(l_value));


        dap_hash_fast (prec->data, prec->len, &prec->csum);                 /* Compute a hash of the payload part of the record */


        log_it(L_DEBUG, "Store object: [%s, %s, %d octets]", l_store_obj.group, l_store_obj.key, l_store_obj.value_len);
                                                                            /* Write has been prepared record in to the DB */
        if ( ret = dap_chain_global_db_driver_add(&l_store_obj, 1) )
            return  log_it(L_ERROR, "Write record to DB, code: %d", ret), ret;
    }

    if ( a_mode )
    {
        for ( struct timespec tmo = {0, 300*1024};  !atomic_load(&l_is_completed); tmo.tv_nsec = 300*1024)
        {
            log_it(L_NOTICE, "Let's finished DB request ...");
            nanosleep(&tmo, &tmo);
        }
    }


    return  0;
}

static int s_test_read(int a_count)
{
dap_store_obj_t *l_store_obj;
int     l_key_nr;
char    l_key[64], l_buf[512];
dap_chain_hash_fast_t csum;
dap_db_test_record_t    *prec;

    log_it(L_NOTICE, "Start reading %d records ...", a_count);

    for (l_key_nr = 0; l_key_nr < a_count; l_key_nr++ )
        {
        snprintf(l_key, sizeof(l_key) - 1, "KEY$%08x", l_key_nr);           /* Generate a key of record */

        if ( !(l_store_obj = dap_chain_global_db_driver_read(DAP_DB$T_GROUP, l_key, NULL)) )
             return  log_it(L_ERROR, "Record-Not-Found for key: %s", l_key), -ENOENT;

        prec = (dap_db_test_record_t *) l_store_obj->value;

        log_it(L_DEBUG, "Retrieved object: [%s, %s, %d octets]", l_store_obj->group, l_store_obj->key, l_store_obj->value_len);

        log_it(L_DEBUG, "Record: ['%.*s', %d octets]", prec->len, prec->data, prec->len);


        dap_hash_fast (prec->data, prec->len, &csum);                       /* Compute a hash of the payload part of the record */

#if 0
        dap_bin2hex (l_buf, prec->csum, sizeof(csum) );
        log_it(L_DEBUG, "%.*s", 2*DAP_HASH_FAST_SIZE, l_buf);
        dap_bin2hex (l_buf, csum, sizeof(csum) );
        log_it(L_DEBUG, "%.*s", 2*DAP_HASH_FAST_SIZE, l_buf);
#endif

        if ( memcmp(&csum, &prec->csum,sizeof(dap_chain_hash_fast_t)) )     /* Integriry checking ... */
             return  log_it(L_ERROR, "Record with key: %s, check sum error", l_key), -EINVAL;
        }

    return  0;
}


static void s_test_close_db(void)
{
    dap_db_driver_deinit();
    log_it(L_NOTICE, "Close global_db");
}


int    main (int argc, char **argv)
{
dap_events_t *l_events;

    dap_set_appname("dap_global_db_test");                                  /* Facility prefix for loggin purpose */

    if ( dap_common_init("db_test", "./dbtest.log", "./" ) )                /* Log to console only ! */
        {
        fprintf(stderr, "dap_common_init() failed, errno=%d", errno);
        return -2;
        }

    // log_it( L_ATT, l_debug_mode ? "*** DEBUG MODE ***" : "*** NORMAL MODE ***" );
    dap_log_level_set( L_NOTICE );

    /* New event loop init */
    dap_events_init( 0, 0 );

    if ( !(l_events = dap_events_new()) )
        return	log_it( L_ERROR, "dap_events_new() failed" ),  -4;

    dap_events_start( l_events );

    /* CuttDB */
    log_it(L_NOTICE, "Start CuttDB R/W test in Sync mode ...");
    s_test_create_db("cdb", 0);
    s_test_write(1350, 0);
    s_test_read(1350);
    s_test_close_db();


    log_it(L_NOTICE, "Start CuttDB R/W test in Async mode ...");
    s_test_create_db("cdb", 1);
    s_test_write(1350, 1);
    s_test_read(1350);
    s_test_close_db();

    /* SQLite3 */
    log_it(L_NOTICE, "Start SQLITE3 R/W test in Sync mode ...");
    s_test_create_db("sqlite", 0);
    s_test_write(1350, 0);
    s_test_read(1350);


    log_it(L_NOTICE, "Start SQLITE3 R/W test in Async mode ...");
    s_test_create_db("sqlite", 1);
    s_test_write(1350, 1);
    s_test_read(1350);

    s_test_close_db();
}
