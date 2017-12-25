#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <time.h>

#include "common.h"
#include "config.h"
#include "dap_client.h"
#include "dap_http_client.h"
#include "enc.h"
#include "enc_key.h"
#include "enc_ks.h"
#include "enc_http.h"
#include "../db/db_core.h"
#include "db_auth.h"

#define LOG_TAG "db_auth"

#define OP_CODE_LOGIN_INCORRECT_PSWD "0xf2"
#define OP_CODE_NOT_FOUND_LOGIN_IN_DB "0xf3"
#define OP_CODE_SUBSCRIBE_EXPIRIED "0xf4"

db_auth_info_t* auths=NULL;

static bool mongod_is_running();
static unsigned char* hash_password(const unsigned char* password, unsigned char* salt, size_t salt_size);

int db_auth_init()
{
    log_it(NOTICE,"Initialized authorization module");

    if(!mongod_is_running())
    {
        return -1;
    }

    return 0;
}

void db_auth_deinit()
{
}

/**
 * @brief db_auth_info_by_cookie Find user by its cookie
 * @param cookie Cookie
 * @return Zero if this cookie is not present
 */
db_auth_info_t* db_auth_info_by_cookie(const char * cookie)
{
    db_auth_info_t * ret = NULL;

    if ( cookie == NULL )
    {
        log_it(ERROR, "cookie is NULL in db_auth_info_by_cookie");
        return NULL;
    }
    HASH_FIND_STR(auths, cookie, ret);
    if(ret == NULL)
        log_it(NOTICE,"Cookie '%s' not present in the table",cookie);
    else
        log_it(INFO,"Cookie '%s' has been found in the table",cookie);
    return ret;
}

db_auth_info_t* db_search_cookie_in_db(const char * cookie)
{
    mongoc_collection_t* collection_cookie = mongoc_client_get_collection
            (mongo_client, my_config.db_name, "dap_cookie_history");

    bson_t *query = bson_new();

    BSON_APPEND_UTF8 (query, "cookie", cookie);

    mongoc_cursor_t *cursor_dap_cookie = mongoc_collection_find
            (collection_cookie, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);

    bson_t *doc_dap_cookie_user;

    if( mongoc_cursor_next (cursor_dap_cookie, (const bson_t**)&doc_dap_cookie_user) == false )
    {
        log_it(INFO, "Cookie not find in database");
        return NULL;
    }

    bson_iter_t iter;

    if ( !(bson_iter_init (&iter, doc_dap_cookie_user) && bson_iter_find (&iter, "login")) )
    {
        log_it(ERROR, "Login not found in document");
        return NULL;
    }

    mongoc_collection_destroy(collection_cookie);
    mongoc_cursor_destroy(cursor_dap_cookie);

    if(doc_dap_cookie_user)
        bson_destroy(doc_dap_cookie_user);

    if(query)
        bson_destroy(query);


    /* ok user find now get information */

    mongoc_collection_t* collection_dap_users = mongoc_client_get_collection
            (mongo_client, my_config.db_name, "dap_users");

    query = bson_new();

    BSON_APPEND_UTF8 (query, "login", bson_iter_value(&iter)->value.v_utf8.str);

    mongoc_cursor_t* cursor_dap_users = mongoc_collection_find
            (collection_dap_users, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);


    if( mongoc_cursor_next (cursor_dap_users, (const bson_t**)&doc_dap_cookie_user) == false )
    {
        log_it(INFO, "User not find in database");
        return NULL;
    }
    // mongoc_collection_destroy(collection_cookie);

    bson_iter_t sub_iter;

    // ok cookie find, get user information;
    db_auth_info_t * ai = CALLOC(db_auth_info_t);

    if (bson_iter_init (&iter, doc_dap_cookie_user) &&
            bson_iter_find_descendant (&iter, "profile.first_name", &sub_iter))
    {
        strncpy(ai->first_name, bson_iter_value(&sub_iter)->value.v_utf8.str,
                bson_iter_value(&sub_iter)->value.v_utf8.len);
    }

    if (bson_iter_init (&iter, doc_dap_cookie_user) &&
            bson_iter_find_descendant (&iter, "profile.last_name", &sub_iter))
    {
        strncpy(ai->last_name,bson_iter_value(&sub_iter)->value.v_utf8.str,
                bson_iter_value(&sub_iter)->value.v_utf8.len);
    }

    if (bson_iter_init (&iter, doc_dap_cookie_user) &&
            bson_iter_find_descendant (&iter, "profile.email", &sub_iter))
    {
        strncpy(ai->email,bson_iter_value(&sub_iter)->value.v_utf8.str,
                    bson_iter_value(&sub_iter)->value.v_utf8.len);
    }

    strcpy(ai->cookie, cookie);

    mongoc_collection_destroy(collection_dap_users);
    mongoc_cursor_destroy(cursor_dap_users);

    if(doc_dap_cookie_user)
        bson_destroy(doc_dap_cookie_user);

    if(query)
        bson_destroy(query);

    HASH_ADD_STR(auths,cookie,ai);

    return ai;
}

/**
 * @brief db_auth_user_change_password
 * @param user
 * @param password
 * @param new_password
 * @return
 * @details change password for user ( check correctly current pass, for change to new )
 */
bool db_auth_user_change_password(const char* user, const char* password,
                                  const char* new_password)
{
    if ( check_user_password(user, password) == false )
    {
        log_it(WARNING, "Error change password. Old user password not correct" , user);
        return false;
    }

    return db_auth_change_password(user, new_password);
}

/**
 * @brief db_auth_user_change_password
 * @param user
 * @param password
 * @param new_password
 * @return
 * @details change passwd without check correct old password ( for admins )
 */
bool db_auth_change_password(const char* user, const char* new_password)
{
    if ( exist_user_in_db(user) == false )
    {
        log_it(WARNING, "Error change password. User %s not find" , user);
        return false;
    }

    mongoc_collection_t *collection_dap_users = mongoc_client_get_collection
            (mongo_client, my_config.db_name, "dap_users");

    bson_t *query = bson_new();

    BSON_APPEND_UTF8 (query, "login", user);

    mongoc_cursor_t *cursor_dap_users = mongoc_collection_find
            (collection_dap_users, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);

    bson_t *doc_dap_user;

    mongoc_cursor_next (cursor_dap_users, (const bson_t**)&doc_dap_user);

    bson_error_t error;

    char salt[8];
    RAND_bytes(salt, 8);

    unsigned const char * password_hash = hash_password(new_password, salt, 8);
    char salt_b64[8*2] = {0};
    enc_base64_encode(salt, 8, salt_b64);

    if (!password_hash) {
        log_it(WARNING,"Can not memmory allocate");
        return false;
    }

    unsigned char * password_hash_b64 = calloc(4 * SHA512_DIGEST_LENGTH, sizeof(char));

    if (!password_hash_b64) {
        free((char*)password_hash);
        log_it(WARNING,"Can not memmory allocate");
        return false;
    }

    enc_base64_encode(password_hash, SHA512_DIGEST_LENGTH * 2, password_hash_b64);


    if (*password_hash_b64 == 0) {
        log_it(WARNING,"Bad hash(based64) for user password");
        return false;
    }

    bson_t *update = BCON_NEW ("$set", "{",
                               "passwordHash", BCON_UTF8 (password_hash_b64),
                               "salt", BCON_UTF8 (salt_b64),"}");

    if (!mongoc_collection_update (collection_dap_users, MONGOC_UPDATE_NONE, doc_dap_user, update, NULL, &error)) {
        log_it(WARNING,"%s", error.message);
        return false;
    }

    mongoc_collection_destroy(collection_dap_users);

    if(query)
        bson_destroy(query);

    if(cursor_dap_users)
        mongoc_cursor_destroy(cursor_dap_users);

    if(doc_dap_user)
        bson_destroy(doc_dap_user);

    free((char*)password_hash); free((char*)password_hash_b64);

    log_it(INFO, "user: %s change password to %s", user, new_password);
    return true;
}


/**
 * @brief check_user_password
 * @param user
 * @param password
 * @return false if user password not correct
 */
bool check_user_password(const char* user, const char* password)
{
    if ( exist_user_in_db(user) == false ){
        log_it(WARNING,"User %s is not present in DB",user);
        return false;
    }

    bool is_correct_password = false;

    mongoc_collection_t *collection = mongoc_client_get_collection (
                mongo_client, my_config.db_name, "dap_users");

    bson_t *query = bson_new();
    BSON_APPEND_UTF8 (query, "login", user);

    bson_iter_t iter;
    bson_t *doc;

    mongoc_cursor_t *cursor =  mongoc_collection_find (collection, MONGOC_QUERY_NONE, 0, 0, 0,
                                                       (const bson_t*)query, NULL, NULL);

    mongoc_cursor_next (cursor, (const bson_t**)&doc);
    char salt[16] = {0}; char salt_from_b64[8] = {0};

    if ( bson_iter_init (&iter, doc) && bson_iter_find (&iter, "salt") )
        memcpy(salt,bson_iter_value(&iter)->value.v_utf8.str,16);
    else {
        log_it(ERROR, "Not find Salt in user"); return NULL;
    }

    enc_base64_decode(salt, 16, salt_from_b64);

    unsigned const char*  password_hash = hash_password(password, salt_from_b64, 8);
    if (!password_hash) {
        log_it(ERROR, "Can not memmory allocate");
        return NULL;
    }

    unsigned char * password_hash_b64 = calloc(4 * SHA512_DIGEST_LENGTH, sizeof(char));

    if (!password_hash_b64) {
        free((char*)password_hash);
        log_it(ERROR, "Can not memmory allocate");
        return NULL;
    }

    enc_base64_encode(password_hash, SHA512_DIGEST_LENGTH * 2, password_hash_b64);

    if (bson_iter_init (&iter, doc) && bson_iter_find (&iter, "passwordHash"))
    {
        if ( memcmp(password_hash_b64, bson_iter_value(&iter)->value.v_utf8.str,
                    SHA512_DIGEST_LENGTH * 2) == 0 )
            is_correct_password = true;
    }

    mongoc_collection_destroy(collection);

    if(cursor)
        mongoc_cursor_destroy(cursor);

    if(query)
        bson_destroy(query);

    if(doc)
        bson_destroy(doc);

    free((char*)password_hash); free((char*)password_hash_b64);

    return is_correct_password;
}


static bool db_auth_save_cookie_inform_in_db(const char* login, char* cookie)
{
    bool result = true;
    mongoc_collection_t *collection = mongoc_client_get_collection (
                mongo_client, my_config.db_name, "dap_cookie_history");

    bson_error_t error;

    bson_t *query = bson_new();
    BSON_APPEND_UTF8 (query, "login", login);

    mongoc_cursor_t *cursor_dap_cookie_history = mongoc_collection_find
            (collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);

    struct tm *utc_date_time;
    time_t t = time(NULL);
    utc_date_time = localtime(&t);

    bson_t *doc_dap_cookie; bson_t *bson_doc = NULL;
    if ( mongoc_cursor_next (cursor_dap_cookie_history, (const bson_t**)&doc_dap_cookie) )
    {
        bson_doc = BCON_NEW ("$set", "{",
                                         "login", BCON_UTF8 (login),
                                         "cookie", BCON_UTF8 (cookie),
                                         "last_use", BCON_DATE_TIME(mktime (utc_date_time) * 1000),
                                      "}");

        if (!mongoc_collection_update (collection, MONGOC_UPDATE_UPSERT, doc_dap_cookie, bson_doc, NULL, &error)) {
            log_it(WARNING,"%s", error.message);
            result = false;
        }
    }
    else
    {
        bson_doc = BCON_NEW("login", BCON_UTF8 (login),
                            "cookie", BCON_UTF8 (cookie),
                            "last_use", BCON_DATE_TIME(mktime (utc_date_time) * 1000));

        if (!mongoc_collection_insert (collection, MONGOC_INSERT_NONE, bson_doc, NULL, &error))
        {
            log_it (WARNING, "%s\n", error.message);
            result = false;
        }
    }

    mongoc_collection_destroy(collection);
    mongoc_cursor_destroy(cursor_dap_cookie_history);
    bson_destroy(query);
    if(doc_dap_cookie)
        bson_destroy(doc_dap_cookie);
    if(bson_doc)
        bson_destroy(bson_doc);

    return result;
}

/**
 * @brief db_auth_login Authorization with user/password
 * @param login ( login = email )
 * @param password Password
 * @param domain
 * @return codes: 1 = login ok, 2 = login not found in DataBase,
 * 3 = incorrect password; 4 = subscribe client has been expiried
 */
int db_auth_login(const char* login, const char* password,
                  const char* domain, db_auth_info_t** ai)
{
    *ai = NULL;
    bson_t *doc;

    mongoc_collection_t *collection = mongoc_client_get_collection (
                mongo_client, my_config.db_name, "dap_users");

    bson_t *query = bson_new();

    if (strchr(login, '@'))
        BSON_APPEND_UTF8 (query, "email", login);
    else
        BSON_APPEND_UTF8 (query, "login", login);

    mongoc_cursor_t *cursor =  mongoc_collection_find (collection, MONGOC_QUERY_NONE, 0, 0, 0,
                                                       (const bson_t*)query, NULL, NULL);

    if ( mongoc_cursor_next (cursor, (const bson_t**)&doc) == false )
    {
        mongoc_cursor_destroy (cursor);
        bson_destroy (query);
        mongoc_collection_destroy (collection);
        log_it(WARNING, "%s not found in DataBase", login);
        return 2;
    }

    bson_iter_t iter;

    char salt[16] = {0}; char salt_from_b64[8]={0};
    if (bson_iter_init (&iter, doc) && bson_iter_find (&iter, "salt"))
        memcpy(salt,bson_iter_value(&iter)->value.v_utf8.str,16);
    else {
        log_it(ERROR, "Not find Salt in user"); return 0;
    }

    enc_base64_decode(salt, 16, salt_from_b64);

    unsigned const char* password_hash = hash_password(password, salt_from_b64, 8);
    if (!password_hash) {
        log_it(ERROR, "Can not memmory allocate");
        return 0;
    }

    unsigned char * password_hash_b64 = calloc(4 * SHA512_DIGEST_LENGTH, sizeof(char));

    if (!password_hash_b64) {
        free((char*)password_hash);
        log_it(ERROR, "Can not memmory allocate");
        return 0;
    }

    enc_base64_encode(password_hash, SHA512_DIGEST_LENGTH * 2, password_hash_b64);

    if (bson_iter_init (&iter, doc) && bson_iter_find (&iter, "expire_date"))
    {
        if ( bson_iter_date_time(&iter) / 1000 < time(NULL) )
        {
            log_it(WARNING, "Subscribe %s has been expiried", login);
            return 4;
        }
    }

    if (bson_iter_init (&iter, doc) && bson_iter_find (&iter, "passwordHash"))
    {
        if ( memcmp(password_hash_b64, bson_iter_value(&iter)->value.v_utf8.str,
                    SHA512_DIGEST_LENGTH * 2) == 0 )
        {
            {
                bool b_error = false;
                mongoc_collection_t *collection_dap_domain = mongoc_client_get_collection
                        (mongo_client, my_config.db_name, "dap_domains");

                bson_t *query = bson_new();

                BSON_APPEND_UTF8 (query, "domain", domain);

                mongoc_cursor_t *cursor_dap_domains =
                        mongoc_collection_find (collection_dap_domain, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);

                bson_t *doc_dap_domain;

                if ( mongoc_cursor_next (cursor_dap_domains, (const bson_t**)&doc_dap_domain) == false )
                {
                    log_it(WARNING, "Login Error! "
                                    "Domain not found in DataBase (collection dap_domains)");

                    b_error = true;
                }

                mongoc_cursor_destroy (cursor_dap_domains);
                bson_destroy (query);
                if(doc_dap_domain)
                    bson_destroy (doc_dap_domain);
                mongoc_collection_destroy (collection_dap_domain);

                if(b_error)
                    return 0;
            }

            log_it(INFO,"Login accepted");

            *ai = CALLOC(db_auth_info_t);
            strncpy((*ai)->user,login,sizeof((*ai)->user));
            strncpy((*ai)->password,password,sizeof((*ai)->password));

            if ( !bson_iter_init (&iter, doc) )
                log_it(ERROR,"Error iter init");

            bson_oid_t oid;

            if ( bson_iter_find(&iter, "_id") )
            {
                bson_oid_init_from_data(&oid, (const uint8_t*) &bson_iter_value(&iter)->value.v_oid.bytes);
                bson_oid_to_string(&oid, (*ai)->id);
            }
            else
                log_it(ERROR,"Not find Id");

            bson_iter_t sub_iter;

            if (bson_iter_init (&iter, doc) &&
                    bson_iter_find_descendant (&iter, "profile.first_name", &sub_iter))
                strncpy((*ai)->first_name,bson_iter_value(&sub_iter)->value.v_utf8.str,
                        sizeof((*ai)->first_name));

            if (bson_iter_init (&iter, doc) &&
                    bson_iter_find_descendant (&iter, "profile.last_name", &sub_iter))
                strncpy((*ai)->last_name,bson_iter_value(&sub_iter)->value.v_utf8.str,
                        sizeof((*ai)->last_name));

            if (bson_iter_init (&iter, doc) &&
                    bson_iter_find_descendant (&iter, "profile.email", &sub_iter))
                strncpy((*ai)->email,bson_iter_value(&sub_iter)->value.v_utf8.str,
                        sizeof((*ai)->email));

            for(int i=0; i < sizeof((*ai)->cookie); i++)
                (*ai)->cookie[i] = 65 + rand() % 25;

            log_it(DEBUG,"Store cookie '%s' in the hash table",(*ai)->cookie);
            db_auth_save_cookie_inform_in_db(login, (*ai)->cookie);
            HASH_ADD_STR(auths,cookie,(*ai));
        }
    }

    free(password_hash_b64);
    free((char*)password_hash);
    mongoc_cursor_destroy (cursor);
    if(query)
        bson_destroy (query);

    if(doc)
        bson_destroy (doc);
    mongoc_collection_destroy (collection);

    if( *ai == NULL )
    {
        log_it (WARNING, "Incorrect password!");
        return 3;
    }
    return 1;
}

/**
 * @brief db_auth_register Register new user in database
 * @param user Login name
 * @param password Password
 * @param first_name First name
 * @param last_name Last name
 * @param email Email
 * @details registerUser
 * @return
 */
db_auth_info_t * db_auth_register(const char *user,const char *password,
                                  const char *domain, const char * first_name,
                                  const char* last_name, const char * email,
                                  const char * device_type,const char *app_version,
                                  const char *hostaddr, const char *sys_uuid )
{
    mongoc_collection_t *collection_dap_domain = mongoc_client_get_collection
                        (mongo_client, my_config.db_name, "dap_domains");

    bson_t *query = bson_new();

    BSON_APPEND_UTF8 (query, "domain", domain);

    mongoc_cursor_t *cursor_dap_domains = mongoc_collection_find
            (collection_dap_domain, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);

    bson_t *doc_dap_domain;

    if ( mongoc_cursor_next (cursor_dap_domains, (const bson_t**)&doc_dap_domain) == false )
    {
        log_it(WARNING, "Domain not found in DataBase (collection dap_domains) ");
        return NULL;
    }

    bson_iter_t iter;
    bson_iter_init (&iter, doc_dap_domain);
    if ( !bson_iter_find (&iter, "_id") )
    {
       log_it(ERROR, "Where field _id in document?!");
       return NULL;
    }

    mongoc_collection_t *collection = mongoc_client_get_collection
                        (mongo_client, my_config.db_name, "dap_users");
    bson_error_t error;

    char salt[8];
    RAND_bytes(salt, 8);

    unsigned const char * password_hash = hash_password(password, salt, 8);
    char salt_b64[8*2] = {0};
    enc_base64_encode(salt, 8, salt_b64);

    if (!password_hash) {
        log_it(ERROR, "Can not memmory allocate");
        return NULL;
    }

    unsigned char * password_hash_b64 = calloc(4 * SHA512_DIGEST_LENGTH, sizeof(char));

    if (!password_hash_b64) {
        free((char*)password_hash);
        log_it(ERROR, "Can not memmory allocate");
        return NULL;
    }

    enc_base64_encode(password_hash, SHA512_DIGEST_LENGTH * 2, password_hash_b64);

    if (*password_hash_b64 == 0) {
        log_it(ERROR, "Bad hash(based64) for user password");
        return NULL;
    }

    bson_t *doc = BCON_NEW("login", user,
                           "passwordHash", password_hash_b64,
                           "salt",salt_b64,
                           "domainId", BCON_OID((bson_oid_t*)bson_iter_value(&iter)->value.v_oid.bytes),
                           "email", email,
                           "profile",
                                "{",
                                    "first_name", first_name,
                                    "last_name", last_name,
                                 "}",
                           "contacts" , "[","]");
    free((char*)password_hash);
    free(password_hash_b64);

    if (!mongoc_collection_insert (collection, MONGOC_INSERT_NONE, doc, NULL, &error)) {
        log_it (WARNING, "%s\n", error.message);

        bson_destroy(query);
        mongoc_collection_destroy (collection_dap_domain);
        bson_destroy(doc_dap_domain);
        mongoc_cursor_destroy(cursor_dap_domains);
        bson_destroy (doc);
        mongoc_collection_destroy (collection);
        mongoc_cleanup();
        return NULL;
    }
    else
    {
        db_auth_info_t * ai = CALLOC(db_auth_info_t);
        strncpy(ai->user,user,sizeof(ai->user));
        strncpy(ai->password,password,sizeof(ai->password));
        strncpy(ai->last_name,last_name,sizeof(ai->last_name));
        strncpy(ai->first_name,first_name,sizeof(ai->first_name));
        strncpy(ai->email,email,sizeof(ai->email));

        for(int i=0;i<sizeof(ai->cookie);i++)
            ai->cookie[i]=65+rand()%25;

        HASH_ADD_STR(auths,cookie,ai);

        bson_destroy(query);
        mongoc_collection_destroy (collection_dap_domain);
        bson_destroy(doc_dap_domain);
        mongoc_cursor_destroy(cursor_dap_domains);
        bson_destroy (doc);
        mongoc_collection_destroy (collection);
        mongoc_cleanup();

        return ai;
    }

    return NULL;
}


/**
 * @brief db_auth_register_channel
 * @param login
 * @param password
 * @details register channel
 * @return
 */
db_auth_info_t * db_auth_register_channel(const char* name_channel, const char* domain,
                                          const char* password)
{
    mongoc_collection_t *collection_dap_domain = mongoc_client_get_collection
                        (mongo_client, my_config.db_name, "dap_domains");

    bson_t *query = bson_new();

    BSON_APPEND_UTF8 (query, "domain", domain);

    mongoc_cursor_t *cursor_dap_domains =
        mongoc_collection_find (collection_dap_domain, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);

    bson_t *doc_dap_domain;

    if ( mongoc_cursor_next (cursor_dap_domains, (const bson_t**)&doc_dap_domain) == false )
    {
        log_it(WARNING, "Domain not found in DataBase (collection dap_domains) ");
        return NULL;
    }

    bson_iter_t iter;
    bson_iter_init (&iter, doc_dap_domain);
    if ( !bson_iter_find (&iter, "_id") )
    {
       log_it(ERROR, "Where field _id in document?!");
       return NULL;
    }

    mongoc_collection_t *collection =
            mongoc_client_get_collection (mongo_client, my_config.db_name, "dap_channels");
    bson_error_t error;

    char salt[8];
    RAND_bytes(salt, 8);
    unsigned const char * password_hash = hash_password(password, salt, 8);

    bson_t *doc = BCON_NEW("name_channel", name_channel,
                           "passwordHash", password_hash,
                           "salt",salt,
                           "domainId", BCON_OID((bson_oid_t*)bson_iter_value(&iter)->value.v_oid.bytes),
                           "subscribers", "[","]",
                           "last_id_message", BCON_INT32(0),
                           "messages","[","]");

    free((char*)password_hash);
    if (!mongoc_collection_insert (collection, MONGOC_INSERT_NONE, doc, NULL, &error)) {
        log_it (ERROR, "%s\n", error.message);
        bson_destroy(query);
        bson_destroy(doc_dap_domain);
        mongoc_cursor_destroy(cursor_dap_domains);
        mongoc_collection_destroy(collection_dap_domain);
        bson_destroy (doc);
        mongoc_collection_destroy (collection);
        mongoc_cleanup();
        return NULL;
    }

    db_auth_info_t * ai = CALLOC(db_auth_info_t);
    strncpy(ai->user,name_channel,sizeof(ai->user));
    strncpy(ai->password,password,sizeof(ai->password));

    for(int i=0;i<sizeof(ai->cookie);i++)
        ai->cookie[i]=65+rand()%25;

    HASH_ADD_STR(auths,cookie,ai);

    bson_destroy(query);
    bson_destroy(doc_dap_domain);
    mongoc_cursor_destroy(cursor_dap_domains);
    mongoc_collection_destroy(collection_dap_domain);
    bson_destroy (doc);
    mongoc_collection_destroy (collection);
    mongoc_cleanup();

    return ai;
}

bool exist_user_in_db(const char* user)
{
    bool exist = true;
    bson_t *doc = NULL;

    mongoc_collection_t *collection = mongoc_client_get_collection (
                mongo_client, my_config.db_name, "dap_users");

    bson_t *query = bson_new();
    BSON_APPEND_UTF8 (query, "login", user);

    mongoc_cursor_t *cursor =  mongoc_collection_find (collection, MONGOC_QUERY_NONE, 0, 0, 0,
                                                       (const bson_t*)query, NULL, NULL);

    if ( mongoc_cursor_next (cursor, (const bson_t**)&doc) == false )
    {
        exist = false;
        log_it(WARNING, "Login not found in DataBase");
    }

    if(doc)
        bson_destroy(doc);

    mongoc_cursor_destroy(cursor);
    bson_destroy(query);
    mongoc_collection_destroy(collection);

    return exist;
}

/**
 * @brief db_auth_http_proc DB Auth http interface
 * @param cl_st HTTP Simple client instance
 * @param arg Pointer to bool with okay status (true if everything is ok, by default)
 */
void db_auth_http_proc(enc_http_delegate_t *dg, void * arg)
{

    if((dg->request)&&(strcmp(dg->action,"POST")==0)){
        if(dg->in_query==NULL){
            log_it(WARNING,"Empty auth action");
            dg->isOk=false;
        }else{
            if(strcmp(dg->in_query,"logout")==0 ){
                db_auth_info_t * ai = db_auth_info_by_cookie(dg->cookie);
                if(ai){
                    log_it(DEBUG, "Cookie from %s user accepted, 0x%032llX session",ai->user,ai->id);
                    HASH_DEL(auths,ai);
                    free(ai);
                    enc_http_reply_f(dg,
                                   "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n"
                                   "<return>Successfuly logouted</return>\n"
                                    );
                }else{
                    log_it(NOTICE,"Logout action: session 0x%032llX is already logouted (by timeout?)",ai->id);
                    enc_http_reply_f(dg,
                                   "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n"
                                   "<err_str>No session in table</err_str>\n"
                                    );
                }

            }else if(strcmp(dg->in_query,"login")==0 ){
                char user[256];
                char password[1024];
                char domain[64];
                    if(sscanf(dg->request_str,"%255s %1023s %63s",user,password,domain)==3){
                        log_it(INFO, "Trying to login with username '%s'",user);
                        if(db_input_validation(user)==0){
                            log_it(WARNING,"Wrong symbols in username '%s'",user);
                            dg->isOk=false;
                            return;
                        }
                        if(db_input_validation(password)==0){
                            log_it(WARNING,"Wrong symbols in password");
                            dg->isOk=false;
                            return;
                        }
                        if(db_input_validation(domain)==0){
                            log_it(WARNING,"Wrong symbols in password");
                            dg->isOk=false;
                            return;
                        }

                        db_auth_info_t * ai = NULL;
                        short login_result = db_auth_login(user, password, domain, &ai);
                        switch (login_result) {
                        case 1:
                            enc_http_reply_f(dg,
                                           "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n"
                                           "<auth_info>\n"
                                            );
                            enc_http_reply_f(dg,"\t<first_name>%s</first_name>\n",ai->first_name);
                            enc_http_reply_f(dg,"\t<last_name>%s</last_name>\n",ai->last_name);
                            enc_http_reply_f(dg,"\t<cookie>%s</cookie>\n",ai->cookie);
                            enc_http_reply_f(dg,"</auth_info>");
                            log_it(INFO, "Login: Successfuly logined user %s",user);
                            break;
                        case 2:
                            enc_http_reply_f(dg, OP_CODE_NOT_FOUND_LOGIN_IN_DB);
                            break;
                        case 3:
                            enc_http_reply_f(dg, OP_CODE_LOGIN_INCORRECT_PSWD);
                            break;
                        case 4:
                            enc_http_reply_f(dg, OP_CODE_SUBSCRIBE_EXPIRIED);
                            break;
                        default:
                            log_it(DEBUG, "Login: wrong password for user %s",user);
                            dg->isOk=false;
                            break;
                        }
                    }else{
                        log_it(DEBUG, "Login: wrong auth's request body ");
                        dg->isOk=false;
                    }
            }else if (strcmp(dg->in_query,"register")==0){
                char user[256];
                char password[1024];
                char domain[64];
                char first_name[1024];
                char last_name[1024];
               // char phone_number[1024];

                char email[1024];
                char device_type[32];
                char app_version[32];
                char sys_uuid[128];

                log_it(INFO, "Request str = %s", dg->request_str);
                if(sscanf(dg->request_str,"%255s %63s %1023s %1023s %1023s %1023s %32s %128s"
                          ,user,password,domain,first_name,last_name,email,device_type,app_version,sys_uuid)>=7){
                    if(db_input_validation(user)==0){
                        log_it(WARNING,"Registration: Wrong symbols in the username '%s'",user);
                        dg->isOk=false;
                        return;
                    }
                    if(db_input_validation(password)==0){
                        log_it(WARNING,"Registration: Wrong symbols in the password");
                        dg->isOk=false;
                        return;
                    }
                    if(db_input_validation(domain)==0){
                        log_it(WARNING,"Registration: Wrong symbols in the password");
                        dg->isOk=false;
                        return;
                    }
                    if(db_input_validation(first_name)==0){
                        log_it(WARNING,"Registration: Wrong symbols in the first name '%s'",first_name);
                        dg->isOk=false;
                        return;
                    }
                    if(db_input_validation(last_name)==0){
                        log_it(WARNING,"Registration: Wrong symbols in the last name '%s'",last_name);
                        dg->isOk=false;
                        return;
                    }
                    if(db_input_validation(email)==0){
                        log_it(WARNING,"Registration: Wrong symbols in the email '%s'",email);
                        dg->isOk=false;
                        return;
                    }

                    db_auth_info_t * ai = db_auth_register(user,password,domain,first_name,last_name,email,
                                                  device_type,app_version,dg->http->client->hostaddr,sys_uuid);

                    if(ai != NULL)
                    {
                        enc_http_reply_f(dg,
                                         "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n"
                                         "<auth_info>\n"
                                         );
                        enc_http_reply_f(dg,"\t<first_name>%s</first_name>\n",ai->first_name);
                        enc_http_reply_f(dg,"\t<last_name>%s</last_name>\n",ai->last_name);
                        enc_http_reply_f(dg,"\t<cookie>%s</cookie>\n",ai->cookie);
                        enc_http_reply_f(dg,"</auth_info>");

                        log_it(NOTICE,"Registration: new user %s \"%s %s\"<%s> is registred",user,first_name,last_name,email);
                    }
                    else {
                        log_it(WARNING, "User not registered. Maybe login already exists");
                    }
                }else{
                    log_it(ERROR, "Registration: Wrong auth's request body ");
                    dg->isOk=false;
                }
            }else{
                log_it(ERROR, "Unknown auth command was selected (query_string='%s')",dg->in_query);
                dg->isOk=false;
            }
        }
    }else{
        log_it(ERROR, "Wrong auth request action '%s'",dg->action);
        dg->isOk=false;
    }
}

static bool mongod_is_running()
{
    int pfd[2];
    pipe(pfd);

    pid_t   childpid;

    if((childpid = fork()) == -1)
    {
        log_it(ERROR,"Error fork()");
        return false;
    }

    if(childpid == 0)
    {
        close(STDOUT_FILENO);
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[0]);
        close(pfd[1]);
        execlp("pgrep", "pgrep","mongod", NULL);
        exit(0);
    }

    waitpid(childpid, 0, 0);

    char readbuffer[10] = {'\0'};

    int flags = fcntl(pfd[0], F_GETFL, 0);
    fcntl(pfd[0], F_SETFL, flags | O_NONBLOCK);
    read(pfd[0], readbuffer, sizeof(readbuffer));

    if(readbuffer[0] == '\0')
    {
        log_it(ERROR,"MongoDB service not running. For start use: \"mongod\" in terminal");
        return false;
    }

    close(pfd[0]);
    close(pfd[1]);

    return true;
}

inline static unsigned char* hash_password(const unsigned char* password, unsigned char* salt, size_t salt_size)
{
    unsigned char *md = (unsigned char*) malloc (SHA512_DIGEST_LENGTH * 2);

    size_t len_pswd = strlen(password);
    size_t length_str = len_pswd + salt_size;
    char str[length_str];

    memcpy(str, password, len_pswd);
    memcpy(str + len_pswd, salt, salt_size);
    SHA512(str, length_str, md);
    SHA512(salt, salt_size, md + SHA512_DIGEST_LENGTH);

    return md;
}

