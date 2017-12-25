#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "common.h"
#include "config.h"

//#include "db_content.h"

#include "dap_http.h"
#include "dap_http_client.h"

#include "enc.h"
#include "enc_key.h"
#include "enc_ks.h"

#define LOG_TAG "db_http_file"

typedef struct db_http_file{
    FILE * fd;
    size_t file_size;
    enc_key_t * key;
    size_t position;
    char path[4096];
    dap_http_client_t * client;
} db_http_file_t;

#define DB_HTTP_FILE(a) ((db_http_file_t*) (a)->internal )


void db_http_file_headers_read(dap_http_client_t * cl_ht, void * arg);
void db_http_file_headers_write(dap_http_client_t * cl_ht, void * arg);
void db_http_file_data_read(dap_http_client_t * cl_ht, void * arg);
void db_http_file_data_write(dap_http_client_t * cl_ht, void * arg);


int db_http_file_init()
{
    return 0;
}

void db_http_file_deinit()
{

}

void db_http_file_proc_add(struct dap_http *sh, const char * url_path)
{
    dap_http_add_proc(sh,url_path,NULL,NULL,NULL,db_http_file_headers_read,db_http_file_headers_write,
                     db_http_file_data_read,db_http_file_data_write,NULL);
}



/**
 * @brief db_http_file_headers_read Signal thats HTTP client is now going to output the data
 * @param cl_ht HTTP client instance
 * @param arg Not used
 */
void db_http_file_headers_read(dap_http_client_t * cl_ht, void * arg)
{
    (void) arg;
    cl_ht->state_write=DAP_HTTP_CLIENT_STATE_START;
    cl_ht->state_read=cl_ht->keep_alive?DAP_HTTP_CLIENT_STATE_START:DAP_HTTP_CLIENT_STATE_NONE;
    dap_client_ready_to_write(cl_ht->client,true);
    dap_client_ready_to_read(cl_ht->client,cl_ht->keep_alive);
}

/**
 * @brief db_http_file_headers Prepare response HTTP headers for file folder request
 * @param cl_ht HTTP client instane
 * @param arg Not used
 */
void db_http_file_headers_write(dap_http_client_t * cl_ht, void * arg)
{
    (void) arg;

    enc_key_t * key= enc_ks_find_http(cl_ht);
    if(key){
        uint8_t buf[sizeof(cl_ht->url_path)];
        size_t buf_size=0;
        size_t url_path_size=strlen(cl_ht->url_path);

        if(url_path_size){
            if(url_path_size>sizeof(cl_ht->url_path)){
                log_it(WARNING, "Too big URL path %lu bytes, shrinking to %lu",url_path_size,sizeof(cl_ht->url_path));
                url_path_size=sizeof(cl_ht->url_path);
            }
            buf_size=enc_decode(key,cl_ht->url_path,url_path_size,buf,ENC_DATA_TYPE_B64);

            uint8_t file_variant=0;
            if(strcmp(buf,"poster_small")==0){
                file_variant=1;
            }else if(strcmp(buf,"poster_big")==0){
                file_variant=2;
            }
            if(file_variant){
                size_t in_query_string_length=strlen(cl_ht->in_query_string);

                if(in_query_string_length){
                    long long cnt_id;
                    buf_size=enc_decode(key,cl_ht->in_query_string,in_query_string_length,buf,ENC_DATA_TYPE_B64);
                    if(sscanf(buf,"id=%lld",&cnt_id)==1){
                        char buf2[255];
                        snprintf(buf2,sizeof(buf2)-1,"id=%lld",cnt_id);
                     //   db_content_t * cnt=db_content_select(buf2); //erase
                        void * cnt = NULL;
                        if(cnt){
                            // Produce local path for file to open
                            char * file_path=NULL;

                            /* ERASE */
                            /*
                            if(file_variant==1)
                                file_path=cnt->poster_small;
                            else if( file_variant==2)
                                file_path=cnt->poster_big;*/

                            if(file_path){
                                // Init specific file response data for HTTP client instance
                                cl_ht->internal=(db_http_file_t *) calloc (1,sizeof(db_http_file_t));
                                db_http_file_t* cl_ht_file=DB_HTTP_FILE(cl_ht);
                                cl_ht_file->client=cl_ht;
                                cl_ht_file->key=key;


                                snprintf(cl_ht_file->path,sizeof(cl_ht_file->path),"%s/%s", my_config.contents_path, file_path );

                                log_it(DEBUG, "Check %s file", cl_ht_file->path);

                                struct stat file_stat;
                                if(stat(cl_ht_file->path,&file_stat)==0){
                                    cl_ht->out_last_modified=file_stat.st_mtime;
                                    cl_ht->out_content_length=(file_stat.st_size%AES_BLOCK_SIZE )?
                                                (file_stat.st_size +(AES_BLOCK_SIZE- (file_stat.st_size%AES_BLOCK_SIZE) )):
                                                file_stat.st_size;
                                    cl_ht_file->file_size=file_stat.st_size;
                                    cl_ht_file->fd=fopen(cl_ht_file->path,"r");
                                    if(cl_ht_file->fd == NULL){
                                        log_it(ERROR, "Can't open %s: %s",cl_ht_file->path,strerror(errno));
                                        cl_ht->reply_status_code=404;
                                        strncpy(cl_ht->reply_reason_phrase,"Not Found",sizeof(cl_ht->reply_reason_phrase));
                                    }else{
                                        log_it(NOTICE, "Open %s file (%lu bytes raw, %lu bytes encrypted )",cl_ht_file->path,cl_ht_file->file_size,cl_ht->out_content_length);
                                        cl_ht->reply_status_code=200;
                                        dap_client_ready_to_write(cl_ht->client,true);
                                        strncpy(cl_ht->reply_reason_phrase,"OK",sizeof(cl_ht->reply_reason_phrase));
                                    }

                                }else{
                                    log_it(WARNING, "Can't get file info: %s",strerror(errno));
                                    cl_ht->reply_status_code=404;
                                    strncpy(cl_ht->reply_reason_phrase,"Not Found",sizeof(cl_ht->reply_reason_phrase));
                                }
                            }else{
                                log_it(WARNING, "Unknown file variant %uc",file_variant);
                                cl_ht->reply_status_code=404;
                                strncpy(cl_ht->reply_reason_phrase,"Not Found",sizeof(cl_ht->reply_reason_phrase));
                            }
                        }else{
                            log_it(WARNING, "Can't find id %lld in database",cnt_id);
                            cl_ht->reply_status_code=404;
                            strncpy(cl_ht->reply_reason_phrase,"Not Found",sizeof(cl_ht->reply_reason_phrase));
                        }
                    }else{
                        log_it(WARNING, "Can't parse decoded in query string '%s'",buf);
                        cl_ht->reply_status_code=500;
                        strncpy(cl_ht->reply_reason_phrase,"Not Found",sizeof(cl_ht->reply_reason_phrase));
                    }
                }else{
                    log_it(WARNING, "Empty in query string");
                    cl_ht->reply_status_code=404;
                    strncpy(cl_ht->reply_reason_phrase,"Not Found",sizeof(cl_ht->reply_reason_phrase));
                }
            }else{
                log_it(WARNING, "Wrong path request (decoded string '%s' )", buf );
                cl_ht->reply_status_code=500;
                strncpy(cl_ht->reply_reason_phrase,"ERROR",sizeof(cl_ht->reply_reason_phrase));
            }
        }else{

            log_it(WARNING, "Empty url path");
            cl_ht->reply_status_code=500;
            strncpy(cl_ht->reply_reason_phrase,"ERROR",sizeof(cl_ht->reply_reason_phrase));
        }
    }else{
        log_it(WARNING, "No KeyID in request");
        cl_ht->reply_status_code=500;
        strncpy(cl_ht->reply_reason_phrase,"ERROR",sizeof(cl_ht->reply_reason_phrase));
    }
}

/**
 * @brief db_http_file_read HTTP client callback for reading function for the folder processing
 * @param cl_ht HTTP client instance
 * @param arg Pointer to int with return bytes number
 */
void db_http_file_data_read(dap_http_client_t * cl_ht, void * arg)
{
    int * bytes_return = (int*) arg; // Return number of read bytes
    //Do nothing
    *bytes_return=cl_ht->client->buf_in_size;
}

/**
 * @brief db_http_folder_write HTTP client callback for writting function for the folder processing
 * @param cl_ht HTTP client instance
 * @param arg
 */
void db_http_file_data_write(dap_http_client_t * cl_ht, void * arg)
{
    (void) arg;
    db_http_file_t * cl_ht_file= DB_HTTP_FILE(cl_ht);

    uint8_t buf[AES_BLOCK_SIZE*200]; // We thing that its dividing on AES_BLOCKSIZE to have no trailing zeros in encrypted block
    size_t buf_size_max=sizeof(buf);
    if(cl_ht_file->file_size- cl_ht_file->position<buf_size_max)
        buf_size_max=(cl_ht_file->file_size- cl_ht_file->position);

    if(buf_size_max){
        size_t buf_size=0;
        buf_size+=fread(buf+buf_size,1,buf_size_max-buf_size,cl_ht_file->fd);

        cl_ht_file->position+=buf_size;
        cl_ht->client->buf_out_size=enc_code(cl_ht_file->key, buf,buf_size,cl_ht->client->buf_out,ENC_DATA_TYPE_RAW);
  //      log_it(DEBUG, "Have read %lu bytes from the file (ecrypted size %lu total size %lu expecting %lu)",buf_size,cl_ht->client->buf_out_size,cl_ht_file->position, cl_ht_file->client->out_content_length);
        if(feof(cl_ht_file->fd)!=0){
            log_it(INFO, "All the file %s is sent out (%lu bytes)",cl_ht_file->path,cl_ht_file->position);
            //strncat(cl_ht->client->buf_out+cl_ht->client->buf_out_size,"\r\n",sizeof(cl_ht->client->buf_out));
            fclose(cl_ht_file->fd);
            dap_client_ready_to_write(cl_ht->client,false);
            cl_ht->client->signal_close=!cl_ht->keep_alive;
            cl_ht->state_write=DAP_HTTP_CLIENT_STATE_NONE;
        }
    }else{
        log_it(INFO, "All the file %s is sent out (%lu bytes)",cl_ht_file->path,cl_ht_file->position);
        fclose(cl_ht_file->fd);
        dap_client_ready_to_write(cl_ht->client,false);
        cl_ht->client->signal_close=!cl_ht->keep_alive;
        cl_ht->state_write=DAP_HTTP_CLIENT_STATE_NONE;
    }
}

