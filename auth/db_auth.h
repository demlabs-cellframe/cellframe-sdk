#ifndef STREAM_AUTH_H
#define STREAM_AUTH_H
#include <stdint.h>
#include "uthash.h"

#include "enc_http.h"

typedef struct db_auth_info{
    char cookie[65];
    char id[27];
    char first_name[1024];
    char last_name[1024];
    char email[1024];
    char user[256];
    char password[1024];
    UT_hash_handle hh; // makes this structure hashable with UTHASH library
} db_auth_info_t;

extern int db_auth_init();
extern void db_auth_deinit();


extern db_auth_info_t* db_auth_info_by_cookie(const char * cookie);
extern db_auth_info_t* db_search_cookie_in_db(const char * cookie);

extern int db_auth_login(const char* login, const char* password,
                              const char* domain, db_auth_info_t** ai);

extern db_auth_info_t * db_auth_register(const char *user,const char *password,
                                         const char *domain, const char * first_name,
                                         const char* last_name, const char * email,
                                         const char * device_type, const char *app_version,
                                         const char *hostaddr, const char *sys_uuid);

extern db_auth_info_t * db_auth_register_channel(const char* name_channel, const char* domain,
                                                 const char* password);
extern bool exist_user_in_db(const char* user);

extern bool db_auth_user_change_password(const char* user, const char* password,
                                  const char* new_password);

extern bool db_auth_change_password(const char *user, const char* new_password);

extern bool check_user_password(const char* user, const char* password);

extern void db_auth_http_proc(enc_http_delegate_t *dg, void * arg);
#endif
