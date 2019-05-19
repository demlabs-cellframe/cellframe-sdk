/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <libgen.h>
#include "dap_common.h"
#include "dap_client_remote.h"

#include "../dap_http.h"
#include "../http_status_code.h"

#include "dap_http_header.h"
#include "dap_http_client.h"

#define LOG_TAG "dap_http_client"

#define BUF_SIZE 2048

void dap_http_client_out_header_generate(dap_http_client_t *cl_ht);

/**
 * @brief dap_http_client_init Init HTTP client module
 * @return  Zero if ok others if not
 */
int dap_http_client_init()
{
    log_it(L_NOTICE,"Initialized HTTP client module");
    return 0;
}

/**
 * @brief dap_http_client_deinit Deinit HTTP client module
 */
void dap_http_client_deinit()
{
    log_it(L_INFO,"HTTP client module deinit");
}

/**
 * @brief dap_http_client_new Creates HTTP client's internal structure
 * @param cl HTTP Client instance
 * @param arg Additional argument (usualy not used)
 */
void dap_http_client_new(dap_client_remote_t * cl,void * arg)
{
    (void) arg;
    cl->_inheritor = DAP_NEW_Z(dap_http_client_t);
    dap_http_client_t * cl_ht = DAP_HTTP_CLIENT(cl);
    cl_ht->client = cl;
    cl_ht->http= DAP_HTTP(cl->server);
    cl_ht->state_read = DAP_HTTP_CLIENT_STATE_START;
    cl_ht->state_write = DAP_HTTP_CLIENT_STATE_NONE;

}

/**
 * @brief dap_http_client_delete
 * @param cl HTTP Client instance
 * @param arg Additional argument (usualy not used)
 */
void dap_http_client_delete(dap_client_remote_t * cl,void * arg)
{
    dap_http_client_t * cl_ht = DAP_HTTP_CLIENT(cl);
    while(cl_ht->in_headers)
        dap_http_header_remove(&cl_ht->in_headers, cl_ht->in_headers);

    while(cl_ht->out_headers)
        dap_http_header_remove(&cl_ht->out_headers, cl_ht->out_headers);

    if(cl_ht->proc)
        if(cl_ht->proc->delete_callback)
            cl_ht->proc->delete_callback(cl_ht,NULL);

    if(cl_ht->_inheritor)
        free(cl_ht->_inheritor);
    (void) arg;
}


/**
 * @brief detect_end_of_line Detect end of line, return position of its end (with \n symbols)
 * @param buf Input buffer
 * @param max_size Maximum size of this buffer minus 1 (for terminating zero)
 * @return position of the end of line
 */
int detect_end_of_line(const char * buf, size_t max_size)
{
    size_t i;
    for(i=0;i<max_size; i++){
        if(buf[i]=='\n'){
            return i;
        }
    }
    return -1;
}

bool dap_http_request_line_parse(dap_http_client_t * cl_ht, char * buf, size_t buf_length)
{
    size_t pos;
    size_t pos_kw_begin=0;
    enum parse_state{PS_START=0, PS_ACTION=1, PS_URL=2, PS_TYPE=3, PS_VER_MAJOR=4, PS_VER_MINOR=5}  p_st=PS_ACTION;
    for(pos=0;pos<buf_length; pos++){
        if(buf[pos]=='\n'){
            break;
        }else if(( buf[pos]==' ')||( buf[pos]=='\t')){
            switch(p_st){
                case PS_ACTION:{
                    size_t c_size= ((pos-pos_kw_begin+1)>sizeof(cl_ht->action) )?
                                (sizeof(cl_ht->action)-1) :
                                (pos-pos_kw_begin) ;
                    memcpy(cl_ht->action, buf+pos_kw_begin,c_size );
                    cl_ht->action[c_size]='\0';
                    //log_it(L_DEBUGUG, "Input: action '%s' pos=%lu pos_kw_begin=%lu", cl_ht->action,pos,pos_kw_begin);
                    p_st=PS_URL;
                    pos_kw_begin=pos+1;
                }break;
                case PS_URL:{
                    size_t c_size= ((pos-pos_kw_begin+1)>sizeof(cl_ht->action) )?
                                (sizeof(cl_ht->url_path)-1) :
                                (pos-pos_kw_begin) ;
                    memcpy(cl_ht->url_path, buf+pos_kw_begin,c_size );
                    cl_ht->url_path[c_size]='\0';
                    //log_it(L_DEBUGUG, "Input: url '%s' pos=%lu pos_kw_begin=%lu", cl_ht->url_path,pos,pos_kw_begin);
                    p_st=PS_TYPE;
                    pos_kw_begin=pos+1;
                }break;
                default:
                    break;
            }
        }else{
            switch(p_st){
                case PS_START:{
                    p_st=PS_ACTION;
                    pos_kw_begin=pos;
                };break;
                default:break;
            }
        }
    }
    return cl_ht->url_path[0]&&cl_ht->action[0];
}

/**
 * @brief dap_http_client_read
 * @param cl HTTP Client instance
 * @param arg Additional argument (usualy not used)
 */
void dap_http_client_read(dap_client_remote_t * cl,void * arg)
{

    (void) arg;
    dap_http_client_t * cl_ht=DAP_HTTP_CLIENT(cl);
    char buf_line[4096];
//    log_it(L_DEBUGUG,"HTTP client in state read %d taked bytes in input %lu",cl_ht->state_read,cl->buf_in_size);
cnt:switch(cl_ht->state_read){
        case DAP_HTTP_CLIENT_STATE_START:{ // Beginning of the session. We try to detect
            int eol = detect_end_of_line(cl->buf_in,cl->buf_in_size);
            if(eol<0){
                return;
            }else if((eol+3)<sizeof(buf_line) ){
                memcpy(buf_line,cl->buf_in,eol+1);
                dap_client_remote_shrink_buf_in(cl,eol+1);
                buf_line[eol+2]='\0';
                if( dap_http_request_line_parse(cl_ht,buf_line,eol+1) ){
                    char * query_string;

                    if( query_string = strchr(cl_ht->url_path,'?'))
                    {
                        size_t len_after=strlen(query_string+1);
                        if(len_after){
                            if(len_after>(sizeof(cl_ht->in_query_string)-1))
                                len_after=sizeof(cl_ht->in_query_string)-1;

                            if(strstr(query_string, "HTTP/1.1"))
                                strncpy(cl_ht->in_query_string,query_string+1,len_after - 11);
                            else
                                strncpy(cl_ht->in_query_string,query_string+1,len_after);

                            if(cl_ht->in_query_string[strlen(cl_ht->in_query_string) - 1] == ' ')
                                cl_ht->in_query_string[strlen(cl_ht->in_query_string) - 1] = '\0';
                            query_string[0]='\0';
                        }
                    }
                    //log_it(NOTICE, "Input: %s request for %s document (query string '%s')",cl_ht->action,cl_ht->url_path, cl_ht->in_query_string? cl_ht->in_query_string: "");
                    char *b_name;
                    char * url_cpy1, *url_cpy2;
                    url_cpy1=strdup(cl_ht->url_path);
                    url_cpy2=strdup(cl_ht->url_path);


                    b_name=basename(url_cpy2);

                    strncpy(cl_ht->url_path,b_name,sizeof(cl_ht->url_path));
                    char * d_name;
                    d_name=dirname(url_cpy1);
                    dap_http_url_proc_t * url_proc;

                    HASH_FIND_STR(cl_ht->http->url_proc, d_name , url_proc);  // Find URL processor

                    cl_ht->proc=url_proc;
                    if(url_proc) {
                        cl_ht->state_read=DAP_HTTP_CLIENT_STATE_HEADERS;
                    }
                    else{
                        log_it(L_WARNING, "Input: unprocessed URL request %s is rejected", d_name);
                        cl_ht->state_read=DAP_HTTP_CLIENT_STATE_NONE;
                        dap_client_remote_ready_to_read(cl_ht->client,true);
                        dap_client_remote_ready_to_write(cl_ht->client,true);
                        cl_ht->reply_status_code=505;
                        strcpy(cl_ht->reply_reason_phrase,"Error");
                        cl_ht->state_write=DAP_HTTP_CLIENT_STATE_START;
                        cl->buf_in_size=0;
                        free(url_cpy1);
                        free(url_cpy2);
                        break;
                    }

                    // cl_ht->state_read=DAP_HTTP_CLIENT_STATE_HEADERS;

                    //free(d_name);
                    //free(b_name);
                    free(url_cpy1);
                    free(url_cpy2);
                }else{
                    log_it(L_WARNING, "Input: Wrong request line '%s'",buf_line);
                    cl->buf_in_size=0;
                    cl_ht->state_read=DAP_HTTP_CLIENT_STATE_NONE;
                    dap_client_remote_ready_to_read(cl_ht->client,false);
                    dap_client_remote_ready_to_write(cl_ht->client,true);
                    cl_ht->reply_status_code=505;
                    strcpy(cl_ht->reply_reason_phrase,"Error");
                    cl_ht->state_write=DAP_HTTP_CLIENT_STATE_START;
                }
            }else{
                log_it(L_WARNING,"Too big line in request, more than %llu symbols - thats very strange",sizeof(buf_line)-3);
                cl->buf_in_size=0;
                cl_ht->state_read=DAP_HTTP_CLIENT_STATE_NONE;
                dap_client_remote_ready_to_read(cl_ht->client,false);
                dap_client_remote_ready_to_write(cl_ht->client,true);
                cl_ht->reply_status_code=505;
                strcpy(cl_ht->reply_reason_phrase,"Error");
                cl_ht->state_write=DAP_HTTP_CLIENT_STATE_START;
            }
        }break;
        case DAP_HTTP_CLIENT_STATE_HEADERS:{ // Parse input headers
            int eol = detect_end_of_line(cl->buf_in,cl->buf_in_size);
            if(eol<0)
                return;
            else{
                int parse_ret;
                memcpy(buf_line,cl->buf_in,eol+1);
                buf_line[eol-1]='\0';

                parse_ret=dap_http_header_parse(cl_ht,buf_line);
              //  log_it(L_WARNINGNG, "++ ALL HEADERS TO PARSE [%s]", buf_line);
                if(parse_ret<0)
                    log_it(L_WARNING,"Input: not a valid header '%s'",buf_line);
                else if(parse_ret==1){
                    log_it(L_INFO,"Input: HTTP headers are over");
                    if(cl_ht->proc->access_callback){
                        bool isOk=true;
                        cl_ht->proc->access_callback(cl_ht,&isOk);
                        if(!isOk){
                            log_it(L_NOTICE,"Access restricted");
                            cl_ht->state_read=DAP_HTTP_CLIENT_STATE_NONE;
                            dap_client_remote_ready_to_read(cl_ht->client,false);
                            dap_client_remote_ready_to_write(cl_ht->client,true);
                            cl_ht->reply_status_code=505;
                            strcpy(cl_ht->reply_reason_phrase,"Error");
                            cl_ht->state_write=DAP_HTTP_CLIENT_STATE_START;
                        }
                    }

                    if(cl_ht->proc->headers_read_callback)
                        cl_ht->proc->headers_read_callback(cl_ht,NULL);

                     // If no headers callback we go to the DATA processing
                    if(cl_ht->in_content_length) {
                        cl_ht->state_read=DAP_HTTP_CLIENT_STATE_DATA;
                    } else {
                        //log_it
                        //cl_ht->state_read=DAP_HTTP_CLIENT_STATE_NONE;
                        //cl_ht->client->ready_to_read=t;
                        //cl_ht->client->signal_close=!cl_ht->keep_alive;
                    }

                }
                dap_client_remote_shrink_buf_in(cl,eol+1);
            }
        }break;
        case DAP_HTTP_CLIENT_STATE_DATA:{//Read the data
         //   log_it(L_WARNINGNG, "DBG_#002 [%s] [%s]",             cl_ht->in_query_string, cl_ht->url_path);

            size_t read_bytes = 0;
            if(cl_ht->proc->data_read_callback){
                //while(cl_ht->client->buf_in_size){
                    cl_ht->proc->data_read_callback(cl_ht,&read_bytes);
                    dap_client_remote_shrink_buf_in(cl,read_bytes);
                //}
            }else {
                log_it(L_WARNING, "data_read callback is NULL in DAP_HTTP_CLIENT_STATE_DATA");
                cl->buf_in_size=0;
            }
        } break;
        case DAP_HTTP_CLIENT_STATE_NONE:{
                cl->buf_in_size=0;
        }break;

    }
    if(cl->buf_in_size>0){
        //log_it(L_DEBUGUG,"Continue to process to parse input");
        goto cnt;
    }
}

/**
 * @brief dap_http_client_write Process write event
 * @param cl HTTP Client instance
 * @param arg Additional argument (usualy not used)
 */
void dap_http_client_write(dap_client_remote_t * cl,void * arg)
{

    (void) arg;
    dap_http_client_t * cl_ht=DAP_HTTP_CLIENT(cl);
 //   log_it(L_DEBUGUG,"HTTP client write callback in state %d",cl_ht->state_write);
    switch(cl_ht->state_write){
        case DAP_HTTP_CLIENT_STATE_NONE: return;
        case DAP_HTTP_CLIENT_STATE_START:{
            if(cl_ht->proc)
                if(cl_ht->proc->headers_write_callback)
                    cl_ht->proc->headers_write_callback(cl_ht,NULL);
            log_it(L_DEBUG,"Output: HTTP response with %u status code",cl_ht->reply_status_code);
            dap_client_remote_write_f(cl,"HTTP/1.1 %u %s\r\n",cl_ht->reply_status_code, cl_ht->reply_reason_phrase[0] ?
                        cl_ht->reply_reason_phrase : http_status_reason_phrase(cl_ht->reply_status_code));
            dap_http_client_out_header_generate(cl_ht);

            cl_ht->state_write=DAP_HTTP_CLIENT_STATE_HEADERS;
        }break;
        case DAP_HTTP_CLIENT_STATE_HEADERS:{
            dap_http_header_t * hdr=cl_ht->out_headers;
            if(hdr==NULL){
                log_it(L_DEBUG, "Output: headers are over (reply status code %u)",cl_ht->reply_status_code);
                dap_client_remote_write_f(cl,"\r\n");
                if(cl_ht->out_content_length || cl_ht->out_content_ready){
                    cl_ht->state_write=DAP_HTTP_CLIENT_STATE_DATA;
                }else{
                    log_it(L_DEBUG,"Nothing to output");
                    cl_ht->state_write=DAP_HTTP_CLIENT_STATE_NONE;
                    dap_client_remote_ready_to_write(cl,false);

                    cl->signal_close=true;
                }
                dap_client_remote_ready_to_read(cl,true);
            }else{
                //log_it(L_DEBUGUG,"Output: header %s: %s",hdr->name,hdr->value);
                dap_client_remote_write_f(cl,"%s: %s\r\n",hdr->name,hdr->value);
                dap_http_header_remove(&cl_ht->out_headers, hdr);
            }
        }break;
        case DAP_HTTP_CLIENT_STATE_DATA:{
            if(cl_ht->proc)
                if(cl_ht->proc->data_write_callback)
                    cl_ht->proc->data_write_callback(cl_ht,NULL);
        }break;
    }
}

/**
 * @brief dap_http_client_out_header_generate Produce general headers
 * @param cl_ht HTTP client instance
 */
void dap_http_client_out_header_generate(dap_http_client_t *cl_ht)
{
    char buf[1024];
    time_t current_time=time(NULL);
    dap_time_to_str_rfc822(buf,sizeof(buf),current_time);
    dap_http_header_add(&cl_ht->out_headers,"Date",buf);
    if(cl_ht->reply_status_code==200){
        if(cl_ht->out_last_modified){
            dap_time_to_str_rfc822(buf,sizeof(buf),cl_ht->out_last_modified);
            dap_http_header_add(&cl_ht->out_headers,"Last-Modified",buf);
        }
        if(cl_ht->out_content_type[0]){
            dap_http_header_add(&cl_ht->out_headers,"Content-Type",cl_ht->out_content_type);
            log_it(L_DEBUG,"output: Content-Type = '%s'",cl_ht->out_content_type);
        }
        if(cl_ht->out_content_length){
            snprintf(buf,sizeof(buf),"%llu",(unsigned long long)cl_ht->out_content_length);
            dap_http_header_add(&cl_ht->out_headers,"Content-Length",buf);
            log_it(L_DEBUG,"output: Content-Length = %llu",cl_ht->out_content_length);
        }
    }
    if(cl_ht->out_connection_close ||  (!cl_ht->keep_alive) )
        dap_http_header_add(&cl_ht->out_headers,"Connection","Close");
    dap_http_header_add(&cl_ht->out_headers,"Server-Name", cl_ht->http->server_name);
    log_it(L_DEBUG,"Output: Headers generated");
}

/**
 * @brief dap_http_client_error Process errors
 * @param cl HTTP Client instance
 * @param arg Additional argument (usualy not used)
 */
void dap_http_client_error(struct dap_client_remote * cl,void * arg)
{
    (void) arg;
    dap_http_client_t * cl_ht=DAP_HTTP_CLIENT(cl);
    if(cl_ht->proc)
        if(cl_ht->proc->error_callback)
        cl_ht->proc->error_callback(cl_ht,arg);
}
