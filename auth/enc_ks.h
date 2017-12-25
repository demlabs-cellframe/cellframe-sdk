#ifndef _ENC_KS_H_
#define _ENC_KS_H_
#include <time.h>
#include <pthread.h>
#include "uthash.h"
struct dap_http_client;

struct enc_key;
typedef struct enc_ks_key{
    char id[33];
    struct enc_key *key;
    time_t time_created;
    pthread_mutex_t mutex;
    UT_hash_handle hh; // makes this structure hashable with UTHASH library
} enc_ks_key_t;

extern int enc_ks_init();
extern void enc_ks_deinit();

extern enc_ks_key_t * enc_ks_find(const char * v_id);
extern struct enc_key * enc_ks_find_http(struct dap_http_client * http);

//extern enc_ks_key_t * enc_ks_new();
extern enc_ks_key_t * enc_ks_add(struct enc_key * key);
extern void enc_ks_delete(const char *id);

#endif
