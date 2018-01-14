#include "dap_client_internal.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "dap_enc_key.h"
#include "dap_enc.h"
#include "dap_common.h"

#include "../http/dap_http_client_simple.h"
#include "dap_client_internal.h"

#define LOG_TAG "dap_client_internal"

const char s_key_domain_str[]="FZVSsPaYr2TB51L";
dap_enc_key_t * s_key_domain = NULL;
static void s_stage_status_after(dap_client_internal_t * a_client_internal);

void m_enc_init_response(dap_client_t *, void *, size_t);
void m_enc_init_error(dap_client_t *, int);

void m_request_response(void * a_response,size_t a_response_size,void * a_obj);
void m_request_error(int,void *);

/**
 * @brief dap_client_internal_init
 * @return
 */
int dap_client_internal_init()
{
    s_key_domain = dap_enc_key_new_from_str(DAP_ENC_KEY_TYPE_AES, s_key_domain_str);
    return 0;
}

/**
 * @brief dap_client_internal_deinit
 */
void dap_client_internal_deinit()
{
    dap_enc_key_delete(s_key_domain);
    s_key_domain = NULL;
}

/**
 * @brief dap_client_internal_new
 * @param a_client_internal
 */
void dap_client_internal_new(dap_client_internal_t * a_client_internal)
{
    a_client_internal->stage = DAP_CLIENT_STAGE_BEGIN; // start point of state machine
    a_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_DONE;
}

/**
 * @brief dap_client_internal_delete
 * @param a_client_internal
 */
void dap_client_internal_delete(dap_client_internal_t * a_client_internal)
{
    if(a_client_internal->uplink_addr)
        free(a_client_internal->uplink_addr);
    if(a_client_internal->uplink_user)
        free(a_client_internal->uplink_user);
    if(a_client_internal->uplink_password)
        free(a_client_internal->uplink_password);
    if(a_client_internal->session_key_id)
        free(a_client_internal->session_key_id);
}


/**
 * @brief s_client_internal_stage_status_proc
 * @param a_client
 */
static void s_stage_status_after(dap_client_internal_t * a_client_internal)
{
    switch(a_client_internal->stage_status){
        case DAP_CLIENT_STAGE_STATUS_IN_PROGRESS:{
            switch( a_client_internal->stage){
                case DAP_CLIENT_STAGE_ENC:{
                    log_it(L_INFO,"Go to stage ENC: prepare the request");
                    if(s_key_domain == NULL){ // No domain key!
                        log_it(L_ERROR,"Can't init encryption without domain key");
                        a_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
                        s_stage_status_after(a_client_internal); // be carefull to not to loop!
                        break;
                    }

                    char *l_key_str= random_string_create(255);
                    char *l_key_session_data = (char*) calloc(1,256*2);
                    dap_enc_code(s_key_domain,l_key_str,strlen(l_key_str),l_key_session_data,DAP_ENC_DATA_TYPE_B64);


                    a_client_internal->session_key = dap_enc_key_new_from_str(DAP_ENC_KEY_TYPE_AES,l_key_session_data);

                    log_it(L_DEBUG,"Request size %u",strlen(l_key_str));
                    dap_client_internal_request( a_client_internal, DAP_UPLINK_PATH_ENC_INIT "/hsd9jslagd92abgjalp9h",
                                                l_key_str,strlen(l_key_str), m_enc_init_response, m_enc_init_error );

                }break;
                default:{
                    log_it(L_ERROR,"Undefined proccessing actions for stage status %s",
                                dap_client_stage_status_str(a_client_internal->stage_status));
                    a_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
                    s_stage_status_after(a_client_internal); // be carefull to not to loop!
                }
            }
        } break;
        case DAP_CLIENT_STAGE_STATUS_ERROR:{
            log_it(L_ERROR, "Error state, doing callback if present");
            if( a_client_internal->stage_status_error_callback ){
                a_client_internal->stage_status_error_callback(a_client_internal->client,NULL);
                // Expecting that its one-shot callback
                a_client_internal->stage_status_error_callback = NULL;
            }
        } break;
        case DAP_CLIENT_STAGE_STATUS_DONE :{
            if( a_client_internal->stage_status_done_callback ){
                a_client_internal->stage_status_done_callback(a_client_internal->client,NULL);
                // Expecting that its one-shot callback
                a_client_internal->stage_status_done_callback = NULL;
            }
        }break;
        default: log_it(L_ERROR,"Undefined proccessing actions for stage status %s",
                        dap_client_stage_status_str(a_client_internal->stage_status));
    }

    if( a_client_internal->stage_status_callback )
        a_client_internal->stage_status_callback( a_client_internal->client,NULL );
}


/**
 * @brief dap_client_internal_stage_transaction_begin
 * @param a_client_internal
 * @param a_stage_next
 * @param a_done_callback
 */
void dap_client_internal_stage_transaction_begin(dap_client_internal_t * a_client_internal, dap_client_stage_t a_stage_next,
                                                 dap_client_callback_t a_done_callback)
{
    a_client_internal->stage_status_done_callback = a_done_callback;
    a_client_internal->stage = a_stage_next;
    a_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_IN_PROGRESS;
    s_stage_status_after(a_client_internal);
}

/**
 * @brief dap_client_internal_request
 * @param a_client_internal
 * @param a_path
 * @param a_request
 * @param a_request_size
 * @param a_response_proc
 */
void dap_client_internal_request(dap_client_internal_t * a_client_internal, const char * a_path, void * a_request,
                    size_t a_request_size,  dap_client_callback_data_size_t a_response_proc, dap_client_callback_int_t a_response_error)
{
    a_client_internal->request_response_callback = a_response_proc;
    a_client_internal->request_error_callback = a_response_error;
    a_client_internal->is_encrypted = false;
    char l_url[2048];
    if(a_path)
        snprintf(l_url,1024,"http://%s:%u/%s",a_client_internal->uplink_addr, a_client_internal->uplink_port, a_path );
    else
        snprintf(l_url,1024,"http://%s:%u",a_client_internal->uplink_addr, a_client_internal->uplink_port );

    dap_http_client_simple_request(l_url, a_request?"POST":"GET","text/text", a_request, a_request_size,
                                       m_request_response, m_request_error, a_client_internal,NULL);
}

/**
 * @brief dap_client_internal_request_enc
 * @param a_client_internal
 * @param a_path
 * @param a_sub_url
 * @param a_query
 * @param a_request
 * @param a_request_size
 * @param a_response_proc
 * @param a_response_error
 */
void dap_client_internal_request_enc(dap_client_internal_t * a_client_internal, const char * a_path,
                                     const char * a_sub_url, const char * a_query
                                    , void * a_request, size_t a_request_size
                                    ,dap_client_callback_data_size_t a_response_proc
                                     , dap_client_callback_int_t a_response_error)
{
    log_it(L_DEBUG,"Encrypted request: sub_url '%s' query '%s'",a_sub_url?a_sub_url:"", a_query?a_query:"" );
    size_t l_sub_url_size = a_sub_url?strlen(a_sub_url): 0;
    size_t l_query_size = a_query?strlen(a_query):0;
    size_t l_url_size;

    char l_url[1024];
    snprintf(l_url,1024,"http://%s:%u",a_client_internal->uplink_addr, a_client_internal->uplink_port );
    l_url_size = strlen(l_url);

    char *l_sub_url_enc = l_sub_url_size ? (char*) calloc(1,2*l_sub_url_size+16 ): NULL;
    char *l_query_enc = l_query_size ? (char*) calloc(1,l_query_size*2+16 ):NULL;

    size_t l_url_full_size_max  = 2*l_sub_url_size + 2*l_query_size + 5 + l_url_size;
    char * l_url_full = (char*) calloc(1, l_url_full_size_max);

    size_t l_request_enc_size_max = a_request_size ?a_request_size*2+16 : 0;
    char * l_request_enc = a_request_size? (char*) calloc(1,l_request_enc_size_max ) : NULL;
    size_t l_request_enc_size = 0;

    a_client_internal->request_response_callback = a_response_proc;
    a_client_internal->request_error_callback = a_response_error;
    a_client_internal->is_encrypted = true;

    if ( l_sub_url_size )
        dap_enc_code(a_client_internal->session_key,a_sub_url,l_sub_url_size,l_sub_url_enc,DAP_ENC_DATA_TYPE_B64);

    if ( l_query_size )
        dap_enc_code(a_client_internal->session_key,a_query,l_query_size,l_query_enc,DAP_ENC_DATA_TYPE_B64);


    if ( a_request_size )
        l_request_enc_size = dap_enc_code(a_client_internal->session_key, a_request, a_request_size
                                          , l_request_enc, DAP_ENC_DATA_TYPE_RAW );

    if (a_path){
        if( l_sub_url_size ){
            if( l_query_size ){
                snprintf(l_url_full,l_url_full_size_max-1,"%s/%s/%s?%s",l_url,a_path, l_sub_url_enc, l_query_enc );
            }else{
                snprintf(l_url_full,l_url_full_size_max-1,"%s/%s/%s",l_url,a_path, l_sub_url_enc);
            }
        }else{
            snprintf(l_url_full,l_url_full_size_max-1,"%s/%s",l_url,a_path);
        }
    }else{
        snprintf(l_url_full,l_url_full_size_max-1,"%s",l_url);
    }

    char l_key_hdr_str[1024];
    snprintf(l_key_hdr_str,sizeof(l_key_hdr_str),"KeyID: %s",a_client_internal->session_key_id );
    dap_http_client_simple_request(l_url_full, a_request?"POST":"GET","text/text", l_request_enc, l_request_enc_size,
                                       m_request_response, m_request_error, a_client_internal, l_key_hdr_str);
    if( l_sub_url_enc )
        free(l_sub_url_enc);

    if( l_query_enc )
        free(l_query_enc);

    if( l_url_full )
        free(l_url_full);

    if( l_request_enc )
        free(l_request_enc);
}

/**
 * @brief m_request_error
 * @param a_err_code
 * @param a_obj
 */
void m_request_error(int a_err_code, void * a_obj)
{
    dap_client_internal_t * a_client_internal = (dap_client_internal_t *) a_obj;
    a_client_internal->request_error_callback(a_client_internal->client, a_err_code );
}

/**
 * @brief m_request_response
 * @param a_response
 * @param a_response_size
 * @param a_obj
 */
void m_request_response(void * a_response,size_t a_response_size,void * a_obj)
{
    dap_client_internal_t * a_client_internal = (dap_client_internal_t *) a_obj;
    if( a_client_internal->is_encrypted){
        size_t l_response_dec_size_max = a_response_size ?a_response_size*2+16 : 0;
        char * l_response_dec = a_response_size? (char*) calloc(1,l_response_dec_size_max ) : NULL;
        size_t l_response_dec_size = 0;
        if ( a_response_size )
            l_response_dec_size = dap_enc_decode(a_client_internal->session_key,
                                             a_response, a_response_size, l_response_dec, DAP_ENC_DATA_TYPE_RAW );

        a_client_internal->request_response_callback(a_client_internal->client, l_response_dec, l_response_dec_size );

        if( l_response_dec )
            free ( l_response_dec );
    }else{
        a_client_internal->request_response_callback(a_client_internal->client, a_response, a_response_size );
    }
}


/**
 * @brief m_enc_init_response
 * @param a_client
 * @param a_response
 * @param a_response_size
 */
void m_enc_init_response(dap_client_t * a_client, void * a_response,size_t a_response_size)
{
    dap_client_internal_t * l_client_internal = DAP_CLIENT_INTERNAL(a_client);
    if( a_response_size > 10 &&  a_response_size < 50){
        l_client_internal->session_key_id = strdup(a_response);
        log_it(L_DEBUG,"Session Key ID %s",l_client_internal->session_key_id);
        if( l_client_internal->stage == DAP_CLIENT_STAGE_ENC ){ // We are in proper stage
            l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_DONE;
            s_stage_status_after(l_client_internal);
        }else{
            log_it(L_WARNING,"Initialized encryption but current stage is %s (%s)",
                   dap_client_get_stage_str(a_client),dap_client_get_stage_status_str(a_client));
        }
    }else if( a_response_size>1){
        log_it(L_ERROR, "Wrong response (size %u data '%s')",a_response_size,(char*) a_response);
        l_client_internal->last_error = DAP_CLIENT_ERROR_ENC_NO_KEY;
        l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_internal);
    }else{
        log_it(L_ERROR, "Wrong response (size %u)",a_response_size);
        l_client_internal->last_error = DAP_CLIENT_ERROR_ENC_NO_KEY;
        l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_internal);
    }
}

/**
 * @brief m_enc_init_error
 * @param a_client
 * @param a_err_code
 */
void m_enc_init_error(dap_client_t * a_client, int a_err_code)
{
    dap_client_internal_t * l_client_internal = DAP_CLIENT_INTERNAL(a_client);
    //dap_client_internal_t * l_client_internal = DAP_CLIENT_INTERNAL(a_client);
    log_it(L_ERROR,"Can't init ecnryption session, err code %d",a_err_code);

    l_client_internal->last_error = DAP_CLIENT_ERROR_NETWORK_CONNECTION_REFUSE ;
    l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
    s_stage_status_after(l_client_internal);
}
