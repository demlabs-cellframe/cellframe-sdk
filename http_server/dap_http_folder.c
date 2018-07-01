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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <magic.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_client.h"
#include "dap_http.h"
#include "dap_http_client.h"
#include "dap_http_folder.h"


typedef struct dap_http_url_proc_folder{
    char local_path[4096];
    magic_t mime_detector;
} dap_http_url_proc_folder_t;
#define URL_PROC_FOLDER(a) ((dap_http_url_proc_folder_t*) (a)->_inhertior )

typedef struct dap_http_file{
    FILE * fd;
    size_t position;
    char local_path[4096];
    dap_http_client_t * client;
} dap_http_file_t;

#define DAP_HTTP_FILE(a) ((dap_http_file_t*) (a)->_inheritor )

void dap_http_folder_headers_read(dap_http_client_t * cl_ht, void * arg);
void dap_http_folder_headers_write(dap_http_client_t * cl_ht, void * arg);
void dap_http_folder_data_read(dap_http_client_t * cl_ht, void * arg);
void dap_http_folder_data_write(dap_http_client_t * cl_ht, void * arg);


#define LOG_TAG "dap_http_folder"

int dap_http_folder_init()
{
    return 0;
}

void dap_http_folder_deinit()
{

}




/**
 * @brief dap_http_folder_add Add folder for reading to the HTTP server
 * @param sh Server instance
 * @param url_path Beginning part of the URL
 * @param local_path Local path that will be read for
 */
int dap_http_folder_add(dap_http_t *sh, const char * url_path, const char * local_path)
{
    if (!local_path) {
        log_it(L_ERROR,"Directory Path parameter is empty!");
        return -11;
    }
    DIR * dirptr = opendir(local_path);
    if (dirptr == NULL) {
         log_it(L_ERROR,"Directory Not Found!");
         return -11;
    }else{
        log_it(L_NOTICE, "File service for %s => %s ",url_path,local_path);
        closedir(dirptr);
    }

    dap_http_url_proc_folder_t * up_folder=(dap_http_url_proc_folder_t *) calloc(1,sizeof(dap_http_url_proc_folder_t));
    strncpy(up_folder->local_path,local_path,sizeof(up_folder->local_path));

    up_folder->mime_detector=magic_open(MAGIC_SYMLINK|MAGIC_MIME|MAGIC_PRESERVE_ATIME);
     if(up_folder->mime_detector==NULL){
         log_it(L_CRITICAL,"Can't init MIME detection library");
         free(up_folder);
         return -1;
     }

    /* if( 0!= magic_load(up_folder->mime_detector, NULL)){
         log_it(L_CRITICAL, "Can't load MIME magic detection database");
         magic_close(up_folder->mime_detector);
         free(up_folder);
         return -2;
     }*/


    dap_http_add_proc(sh,url_path,up_folder,NULL,NULL,dap_http_folder_headers_read,dap_http_folder_headers_write,
                     dap_http_folder_data_read,dap_http_folder_data_write,NULL);
    return 0;
}

/**
 * @brief dap_http_folder_headers_read Signal thats HTTP client is now going to output the data
 * @param cl_ht HTTP client instance
 * @param arg Not used
 */
void dap_http_folder_headers_read(dap_http_client_t * cl_ht, void * arg)
{
    (void) arg;
    cl_ht->state_write=DAP_HTTP_CLIENT_STATE_START;
    cl_ht->state_read=cl_ht->keep_alive?DAP_HTTP_CLIENT_STATE_START:DAP_HTTP_CLIENT_STATE_NONE;
    dap_client_ready_to_write(cl_ht->client,true);
    dap_client_ready_to_read(cl_ht->client, cl_ht->keep_alive);
}

/**
 * @brief dap_http_folder_headers Prepare response HTTP headers for file folder request
 * @param cl_ht HTTP client instane
 * @param arg Not used
 */
void dap_http_folder_headers_write(dap_http_client_t * cl_ht, void * arg)
{
    (void) arg;
    // Get specific data for folder URL processor
    dap_http_url_proc_folder_t * up_folder=(dap_http_url_proc_folder_t*) cl_ht->proc->_inheritor;

    // Init specific file response data for HTTP client instance
    cl_ht->_inheritor=DAP_NEW_Z(dap_http_file_t);

    dap_http_file_t* cl_ht_file=DAP_HTTP_FILE(cl_ht);
    cl_ht_file->client=cl_ht;

    // Produce local path for file to open
    snprintf(cl_ht_file->local_path,sizeof(cl_ht_file->local_path),"%s/%s", up_folder->local_path, cl_ht->url_path );
    log_it(L_DEBUG, "Check %s file", cl_ht_file->local_path);

    struct stat file_stat;
    if(stat(cl_ht_file->local_path,&file_stat)==0){
        cl_ht->out_last_modified=file_stat.st_mtime;
        cl_ht->out_content_length=file_stat.st_size;
        cl_ht_file->fd=fopen(cl_ht_file->local_path,"r");
        if(cl_ht_file->fd == NULL){
            log_it(L_ERROR, "Can't open %s: %s",cl_ht_file->local_path,strerror(errno));
            cl_ht->reply_status_code=404;
            strncpy(cl_ht->reply_reason_phrase,"Not Found",sizeof(cl_ht->reply_reason_phrase));
        }else{
            cl_ht->reply_status_code=200;
            strncpy(cl_ht->reply_reason_phrase,"OK",sizeof(cl_ht->reply_reason_phrase));

            const char * mime_type = magic_file( up_folder->mime_detector,cl_ht_file->local_path);
            if(mime_type){
                strncpy(cl_ht->out_content_type,mime_type,sizeof(cl_ht->out_content_type));
                log_it(L_DEBUG,"MIME type detected: '%s'",mime_type);
            }else
                log_it(L_WARNING,"Can't detect MIME type of %s file: %s",cl_ht_file->local_path,magic_error(up_folder->mime_detector));
        }

    }else{
        log_it(L_WARNING, "Can't get file info: %s",strerror(errno));
        cl_ht->reply_status_code=404;
        strncpy(cl_ht->reply_reason_phrase,"Not Found",sizeof(cl_ht->reply_reason_phrase));
    }
}

/**
 * @brief dap_http_folder_read HTTP client callback for reading function for the folder processing
 * @param cl_ht HTTP client instance
 * @param arg Pointer to int with return bytes number
 */
void dap_http_folder_data_read(dap_http_client_t * cl_ht, void * arg)
{
    int * bytes_return = (int*) arg; // Return number of read bytes
    //Do nothing
    *bytes_return=cl_ht->client->buf_in_size;
}

/**
 * @brief dap_http_folder_write HTTP client callback for writting function for the folder processing
 * @param cl_ht HTTP client instance
 * @param arg
 */
void dap_http_folder_data_write(dap_http_client_t * cl_ht, void * arg)
{
    (void) arg;
    dap_http_file_t * cl_ht_file= DAP_HTTP_FILE(cl_ht);
    cl_ht->client->buf_out_size=fread(cl_ht->client->buf_out,1,sizeof(cl_ht->client->buf_out),cl_ht_file->fd);
    cl_ht_file->position+=cl_ht->client->buf_out_size;

    if(feof(cl_ht_file->fd)!=0){
        log_it(L_INFO, "All the file %s is sent out",cl_ht_file->local_path);
        //strncat(cl_ht->client->buf_out+cl_ht->client->buf_out_size,"\r\n",sizeof(cl_ht->client->buf_out));
        fclose(cl_ht_file->fd);
        dap_client_ready_to_write(cl_ht->client,false);
        cl_ht->client->signal_close=!cl_ht->keep_alive;
        cl_ht->state_write=DAP_HTTP_CLIENT_STATE_NONE;
    }
}

