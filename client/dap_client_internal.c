#include "dap_client_internal.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "dap_enc_key.h"
#include "dap_enc.h"
#include "dap_enc_base64.h"
#include "dap_common.h"
#include "sxmlc/sxmlc.h"
#include "liboqs/kex_rlwe_msrln16/kex_rlwe_msrln16.h"
#include "liboqs/kex/kex.h"
#include "dap_enc_msrln16.h"

#include "../http/dap_http_client_simple.h"
#include "dap_client_internal.h"

#define LOG_TAG "dap_client_internal"

dap_enc_key_t * s_key_domain = NULL;
static void s_stage_status_after(dap_client_internal_t * a_client_internal);

void m_enc_init_response(dap_client_t *, void *, size_t);
void m_enc_init_error(dap_client_t *, int);

// AUTH stage callbacks
void m_auth_response(dap_client_t *, void *, size_t);
void m_auth_error(dap_client_t *, int);
int m_auth_response_parse(XMLEvent event, const XMLNode* node, SXML_CHAR* text, const int n, SAX_Data* sd);

// STREAM_CTL stage callbacks
void m_stream_ctl_response(dap_client_t *, void *, size_t);
void m_stream_ctl_error(dap_client_t *, int);

void m_request_response(void * a_response,size_t a_response_size,void * a_obj);
void m_request_error(int,void *);

/**
 * @brief dap_client_internal_init
 * @return
 */
int dap_client_internal_init()
{
    OQS_RAND* rand = OQS_RAND_new(OQS_RAND_alg_urandom_chacha20);        
    s_key_domain = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_RLWE_MSRLN16,16);
    dap_enc_msrln16_key_t* msrln16_key = DAP_ENC_KEY_TYPE_RLWE_MSRLN16(s_key_domain);
    msrln16_key->kex = OQS_KEX_rlwe_msrln16_new(rand);
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
                    //Stage 1 : generate private key and alice message
                    dap_enc_msrln16_key_t* msrln16_key = DAP_ENC_KEY_TYPE_RLWE_MSRLN16(s_key_domain);
                    uint8_t* out_msg = NULL;
                    size_t out_msg_size = 0;
                    OQS_KEX_rlwe_msrln16_alice_0(msrln16_key->kex,&msrln16_key->private_key,&out_msg,&out_msg_size);

                    char *sendMsg = malloc(out_msg_size * 2  + 1024);

                    char* encrypt_msg = malloc(out_msg_size * 2);
                    dap_enc_base64_encode(out_msg,out_msg_size, encrypt_msg);

                    strcat(sendMsg,encrypt_msg);

                    dap_client_internal_request( a_client_internal, DAP_UPLINK_PATH_ENC_INIT "/gd4y5yh78w42aaagh",
                        sendMsg,strlen(sendMsg), m_enc_init_response, m_enc_init_error );

                    free(encrypt_msg);
                    free(sendMsg);

                }break;
                case DAP_CLIENT_STAGE_AUTH:{
                    log_it(L_INFO,"Go to stage AUTH: prepare the request");

                    /// uplink_user checks
                    if ( a_client_internal->uplink_user == NULL){
                        log_it(L_ERROR,"Can't AUTH with NULL uplink user");
                        a_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
                        s_stage_status_after(a_client_internal); // be carefull to not to loop!
                        break;
                    }else if ( a_client_internal->uplink_user[0] == 0  ){
                        log_it(L_ERROR,"Can't AUTH with empty uplink user");
                        a_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
                        s_stage_status_after(a_client_internal); // be carefull to not to loop!
                        break;
                    }
                    /// uplink_password checks
                    if ( a_client_internal->uplink_password == NULL){
                        log_it(L_ERROR,"Can't AUTH with NULL uplink password");
                        a_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
                        s_stage_status_after(a_client_internal); // be carefull to not to loop!
                        break;
                    }else if ( a_client_internal->uplink_password[0] == 0  ){
                        log_it(L_ERROR,"Can't AUTH with empty uplink password");
                        a_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
                        s_stage_status_after(a_client_internal); // be carefull to not to loop!
                        break;
                    }

                    size_t l_request_size = strlen( a_client_internal->uplink_user)
                            + strlen( a_client_internal->uplink_password)+2+10;
                    char *l_request = DAP_NEW_Z_SIZE (char,l_request_size) ;

                    snprintf(l_request, l_request_size,"%s %s %d",a_client_internal->uplink_user,
                             a_client_internal->uplink_password, DAP_CLIENT_PROTOCOL_VERSION);
                    log_it(L_DEBUG,"AUTH request size %u",strlen(l_request));

                    // If we was authorized before - reset it
                    if ( a_client_internal->auth_cookie ){
                        DAP_DELETE (a_client_internal->auth_cookie );
                        a_client_internal->auth_cookie = NULL;
                    }
                    // Until we haven't PROTO version before this step - we set the current one
                    a_client_internal->uplink_protocol_version = DAP_PROTOCOL_VERSION;
                    dap_client_internal_request_enc(a_client_internal,
                                                   DAP_UPLINK_PATH_DB,
                                                    "auth","login",l_request,l_request_size,
                                                    m_auth_response, m_auth_error);

                }break;
                case DAP_CLIENT_STAGE_STREAM_CTL:{
                    log_it(L_INFO,"Go to stage STREAM_CTL: prepare the request");

                    size_t l_request_size = strlen( a_client_internal->uplink_user)
                            + strlen( a_client_internal->uplink_password)+2+10;
                    char *l_request = DAP_NEW_Z_SIZE (char,l_request_size) ;

                    snprintf(l_request, l_request_size,"%s %s %d",a_client_internal->uplink_user,
                             a_client_internal->uplink_password, DAP_CLIENT_PROTOCOL_VERSION);
                    log_it(L_DEBUG,"STREAM_CTL request size %u",strlen(l_request));

                    dap_client_internal_request_enc(a_client_internal,
                                                   DAP_UPLINK_PATH_STREAM_CTL,
                                                    "socket_forward","sf=1",l_request,l_request_size,
                                                    m_stream_ctl_response, m_stream_ctl_error);
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
                //a_client_internal->stage_status_error_callback = NULL;
            }
            a_client_internal->stage = DAP_CLIENT_STAGE_ENC;
            // Trying the step again
            a_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_IN_PROGRESS;
            s_stage_status_after(a_client_internal);
        } break;
        case DAP_CLIENT_STAGE_STATUS_DONE :{
            log_it(L_INFO, "Stage status %s is done",
                   dap_client_stage_str(a_client_internal->stage) );
            bool l_is_last_stage=( a_client_internal->stage == a_client_internal->stage_target );
            if( a_client_internal->stage_status_done_callback ){
                a_client_internal->stage_status_done_callback(a_client_internal->client,NULL);
                // Expecting that its one-shot callback
                //a_client_internal->stage_status_done_callback = NULL;
            }else
                log_it(L_WARNING,"Stage done callback is not present");

            if (l_is_last_stage ){
                log_it(L_NOTICE, "Stage %s is achieved",
                       dap_client_stage_str(a_client_internal->stage));
                if( a_client_internal->stage_target_done_callback ){
                    a_client_internal->stage_target_done_callback(a_client_internal->client,NULL);
                    // Expecting that its one-shot callback
                    a_client_internal->stage_target_done_callback = NULL;
                }
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

    dap_http_client_simple_request(l_url, a_request?"POST":"GET","text/text", a_request, a_request_size,NULL,
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
    size_t i;
    dap_enc_data_type_t l_enc_type;

    if( a_client_internal->uplink_protocol_version >= 21  )
        l_enc_type = DAP_ENC_DATA_TYPE_B64_URLSAFE;
    else
        l_enc_type = DAP_ENC_DATA_TYPE_B64;

    if ( l_sub_url_size )
        dap_enc_code(a_client_internal->session_key,a_sub_url,l_sub_url_size,l_sub_url_enc,l_enc_type);

    if ( l_query_size )
        dap_enc_code(a_client_internal->session_key,a_query,l_query_size,l_query_enc,l_enc_type);


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
    if ( a_client_internal->auth_cookie){
        size_t l_cookie_hdr_str_size = strlen(a_client_internal->auth_cookie)+100;
        char * l_cookie_hdr_str= DAP_NEW_Z_SIZE(char,l_cookie_hdr_str_size);
        snprintf(l_cookie_hdr_str,l_cookie_hdr_str_size,"Cookie: %s",a_client_internal->auth_cookie  );

        dap_http_client_simple_request(l_url_full, a_request?"POST":"GET","text/text",
                                       l_request_enc, l_request_enc_size, l_cookie_hdr_str,
                                           m_request_response, m_request_error, a_client_internal, l_key_hdr_str);
        DAP_DELETE(l_cookie_hdr_str);
    }else
        dap_http_client_simple_request(l_url_full, a_request?"POST":"GET","text/text",
                                       l_request_enc, l_request_enc_size, NULL,
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
    if( a_response_size > 2000 &&  a_response_size < 4000){
        if( l_client_internal->stage == DAP_CLIENT_STAGE_ENC ){
            char *msg_index = strchr(a_response,' ');
            int key_size = (void*)msg_index - a_response;
            int msg_size = a_response_size - key_size - 1;
            char* encoded_key = malloc(key_size);
            memset(encoded_key,0,key_size);
            uint8_t *encoded_msg = malloc(msg_size);
            dap_enc_base64_decode(a_response,key_size,encoded_key);
            dap_enc_base64_decode(msg_index+1,msg_size,encoded_msg);
            dap_enc_msrln16_key_t* msrln16_key = DAP_ENC_KEY_TYPE_RLWE_MSRLN16(s_key_domain);
            OQS_KEX_rlwe_msrln16_alice_1(msrln16_key->kex, msrln16_key->private_key, encoded_msg, 2048,&msrln16_key->public_key,&msrln16_key->public_length);
            uint8_t s;
            for(int i=0; i < msrln16_key->public_length;i++)
                s = msrln16_key->public_key[i];
            free(encoded_key);
            free(encoded_msg);
            l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_DONE;
            s_stage_status_after(l_client_internal);
        }
        else{
            log_it(L_WARNING,"Initialized encryption but current stage is %s (%s)",
            dap_client_get_stage_str(a_client),dap_client_get_stage_status_str(a_client));
        }
    }else if( a_response_size>1){
        s_stage_status_after(l_client_internal);
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

/**
 * @brief m_auth_response Process AUTH response
 * @param a_client
 * @param a_data
 * @param a_data_size
 */
void m_auth_response(dap_client_t * a_client, void * a_data, size_t a_data_size)
{
    dap_client_internal_t * l_client_internal = DAP_CLIENT_INTERNAL(a_client);

    log_it(L_DEBUG, "AUTH response %u bytes length recieved", a_data_size);
    char * l_response_str = DAP_NEW_Z_SIZE(char, a_data_size+1);
    memcpy(l_response_str, a_data,a_data_size);

    if(a_data_size <10 ){
        log_it(L_ERROR, "AUTH Wrong reply: '%s'", l_response_str);
    }else{
        XMLDoc l_doc;
        XMLDoc_init(&l_doc);

        SAX_Callbacks l_sax;
        SAX_Callbacks_init(&l_sax);

        l_sax.all_event = m_auth_response_parse;

        XMLDoc_parse_buffer_SAX( C2SX(l_response_str ), C2SX("auth"),&l_sax, a_client );
        XMLDoc_free(&l_doc);

        DAP_DELETE(l_response_str);
        if ( l_client_internal->auth_cookie ){
            log_it(L_DEBUG, "Cookie is present in reply");
            if( l_client_internal->stage == DAP_CLIENT_STAGE_AUTH ){ // We are in proper stage
                l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_DONE;
                s_stage_status_after(l_client_internal);
            }else{
                log_it(L_WARNING,"Expected to be stage AUTH but current stage is %s (%s)",
                       dap_client_get_stage_str(a_client),dap_client_get_stage_status_str(a_client));

            }
        }else {
            if( l_client_internal->last_error == DAP_CLIENT_ERROR_AUTH_WRONG_CREDENTIALS ){
                log_it (L_WARNING, "Wrong user or/and password");
            }else{
                log_it(L_WARNING, "Cookie is not present in reply!");
                l_client_internal->last_error = DAP_CLIENT_ERROR_AUTH_WRONG_COOKIE ;
                l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
            }

            s_stage_status_after(l_client_internal);
        }
    }
}

/**
 * @brief m_auth_response_parse Parse XML reply after authorization
 * @param event
 * @param node
 * @param text
 * @param n
 * @param sd
 * @return
 */
int m_auth_response_parse(XMLEvent event, const XMLNode* node, SXML_CHAR* text, const int n, SAX_Data* sd)
{
    dap_client_t * l_client = (dap_client_t *) sd->user;
    dap_client_internal_t * l_client_internal = DAP_CLIENT_INTERNAL( l_client );

    char * l_node_text =node ? (  node->text? node->text : "(NULL)") : "(NULL)"  ;
    switch (event) {
        //case XML_EVENT_START_NODE: last_parsed_node = strdup ( node->text) return start_node(node, sd);
        case XML_EVENT_TEXT:
//            log_it(L_DEBUG, "Node text '%s'", text );
            if( l_client_internal->last_parsed_node ){
                free(l_client_internal->last_parsed_node);
                l_client_internal->last_parsed_node = NULL;
            }
            l_client_internal->last_parsed_node = strdup(text);
            return true;
        break;
        case XML_EVENT_END_NODE: {
            if(node == NULL)
                break;
           // log_it(L_DEBUG,"Parsed <%s>%s</%s> tag", node->tag, l_client_internal->last_parsed_node
           //        ?l_client_internal->last_parsed_node:"(NULL)", node->tag);
            if (strcmp(node->tag, "err_str") == 0 ){
                log_it(L_ERROR,"Error string in reply: '%s'", l_client_internal->last_parsed_node?l_client_internal->last_parsed_node: "(NULL))" );

                l_client_internal->last_error = DAP_CLIENT_ERROR_AUTH_WRONG_CREDENTIALS ;
                l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
            }else if ( strcmp ( node->tag, "cookie") == 0 ){
                //log_it (L_DEBUG, "Cookie %s", l_client_internal->last_parsed_node?l_client_internal->last_parsed_node:"(NULL)");
                l_client_internal->auth_cookie = strdup (l_client_internal->last_parsed_node?l_client_internal->last_parsed_node:"(NULL)");
            }else if ( strcmp ( node->tag, "server_protocol_version" ) == 0  ){
                if( l_client_internal->last_parsed_node ) {
                    sscanf(l_client_internal->last_parsed_node,"%u",&l_client_internal->uplink_protocol_version);
                    if (l_client_internal->uplink_protocol_version == 0){
                        log_it(L_WARNING, "No uplink protocol version, setting up the default, %u",DAP_PROTOCOL_VERSION);
                    }
                    log_it (L_NOTICE, "Uplink protocol version %u", l_client_internal->uplink_protocol_version);
                }

            }
            if( l_client_internal->last_parsed_node ){
                free(l_client_internal->last_parsed_node);
                l_client_internal->last_parsed_node = NULL;
            }
            return true;
        }break;
        default: return true;
        //case XML_EVENT_TEXT: return new_text(text, sd);
    }
    return true;
}

/**
 * @brief m_auth_error
 * @param a_client
 * @param a_error
 */
void m_auth_error(dap_client_t * a_client, int a_error)
{
    log_it(L_WARNING, "AUTH error %d", a_error);
    dap_client_internal_t * l_client_internal = DAP_CLIENT_INTERNAL(a_client);

    l_client_internal->last_error = DAP_CLIENT_ERROR_AUTH_WRONG_REPLY ;
    l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
    s_stage_status_after(l_client_internal);
}

/**
 * @brief m_stream_ctl_response
 * @param a_client
 * @param a_data
 * @param a_data_size
 */
void m_stream_ctl_response(dap_client_t * a_client, void * a_data, size_t a_data_size)
{
    dap_client_internal_t * l_client_internal = DAP_CLIENT_INTERNAL(a_client);

    log_it(L_DEBUG, "STREAM_CTL response %u bytes length recieved", a_data_size);
    char * l_response_str = DAP_NEW_Z_SIZE(char, a_data_size+1);
    memcpy(l_response_str, a_data,a_data_size);

    if( a_data_size<4 ){
        log_it(L_ERROR, "STREAM_CTL Wrong reply: '%s'", l_response_str);
        l_client_internal->last_error = DAP_CLIENT_ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT;
        l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_internal);
    }else if ( strcmp(l_response_str, "ERROR") == 0 ){
        log_it(L_WARNING, "STREAM_CTL Got ERROR from the remote site,expecting thats ERROR_AUTH");
        l_client_internal->last_error = DAP_CLIENT_ERROR_STREAM_CTL_ERROR_AUTH;
        l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_internal);
    }else {
        int l_arg_count;
        char l_stream_id[25]={0};
        char *l_stream_key = DAP_NEW_Z_SIZE(char,4096*3);
        void * l_stream_key_raw = DAP_NEW_Z_SIZE(char,4096);
        size_t l_stream_key_raw_size = 0;
        uint32_t l_remote_protocol_version;

        l_arg_count = sscanf(l_response_str,"%25s %4096s %u"
                             ,l_stream_id,l_stream_key,&l_remote_protocol_version );
        if (l_arg_count <2 ){
            log_it(L_WARNING, "STREAM_CTL Need at least 2 arguments in reply (got %d)",l_arg_count);
            l_client_internal->last_error = DAP_CLIENT_ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT;
            l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
            s_stage_status_after(l_client_internal);
        }else{

            if( l_arg_count >2){
                l_client_internal->uplink_protocol_version = l_remote_protocol_version;
                log_it(L_DEBUG,"Uplink protocol version %u",l_remote_protocol_version);
            }else
                log_it(L_WARNING,"No uplink protocol version, use the default version %d"
                       ,l_client_internal->uplink_protocol_version = DAP_PROTOCOL_VERSION);

            if(strlen(l_stream_id)<13){
                //log_it(L_DEBUG, "Stream server id %s, stream key length(base64 encoded) %u"
                //       ,l_stream_id,strlen(l_stream_key) );
                log_it(L_DEBUG, "Stream server id %s, stream key '%s'"
                       ,l_stream_id,l_stream_key );

                //l_stream_key_raw_size = enc_base64_decode(l_stream_key,strlen(l_stream_key),l_stream_key_raw);
                // Delete old key if present
                if(l_client_internal->stream_key)
                    dap_enc_key_delete(l_client_internal->stream_key);

                strncpy(l_client_internal->stream_id,l_stream_id,sizeof(l_client_internal->stream_id)-1);
                l_client_internal->stream_key = dap_enc_key_new_from_str(DAP_ENC_KEY_TYPE_AES,l_stream_key);

                //streamSocket->connectToHost(SapSession::me()->address(),SapSession::me()->port().toUShort(),QIODevice::ReadWrite);

                if( l_client_internal->stage == DAP_CLIENT_STAGE_STREAM_CTL ){ // We are on the right stage
                    l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_DONE;
                    s_stage_status_after(l_client_internal);
                }else{
                    log_it(L_WARNING,"Expected to be stage STREAM_CTL but current stage is %s (%s)",
                           dap_client_get_stage_str(a_client),dap_client_get_stage_status_str(a_client));

                }
            }else{
                log_it(L_WARNING,"Wrong stream id response");
                l_client_internal->last_error = DAP_CLIENT_ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT;
                l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;
                s_stage_status_after(l_client_internal);
            }

        }
        DAP_DELETE(l_stream_key);
        DAP_DELETE(l_stream_key_raw);
    }
}

/**
 * @brief m_stream_ctl_error
 * @param a_client
 * @param a_error
 */
void m_stream_ctl_error(dap_client_t * a_client, int a_error)
{
   log_it(L_WARNING, "STREAM_CTL error %d",a_error);

   dap_client_internal_t * l_client_internal = DAP_CLIENT_INTERNAL(a_client);

   l_client_internal->last_error = DAP_CLIENT_ERROR_STREAM_CTL_ERROR;
   l_client_internal->stage_status = DAP_CLIENT_STAGE_STATUS_ERROR;

   s_stage_status_after(l_client_internal);

}
