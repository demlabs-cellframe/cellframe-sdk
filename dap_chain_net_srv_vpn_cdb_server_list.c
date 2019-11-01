/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "dap_common.h"

#include "dap_http.h"
#include "dap_enc_http.h"
#include "dap_http_simple.h"
#include "dap_chain_net_srv_vpn_cdb_server_list.h"
#include "dap_enc.h"

#define LOG_TAG "dap_chain_net_srv_vpn_cdb_server_list"

#define HTML_HEAD "<html><head><meta content=\"en-us\" http-equiv=\"Content-Language\"><meta content=\"text/html; charset=utf-8\" http-equiv=\"Content-Type\" /><title>DiveVPN Accessibility Report</title></head><body>"
#define HTML_END "</body></html>"
#define STR_SIZE 2048

#define REPORT_FILE_HEAD "/opt/dapserver/log/accessibility_report.html" // todo move filenae to external config


static char typical_adress[] = "255.255.255.255";

typedef struct server_info
{
    char name[50];
    char address[sizeof(typical_adress)];
    char  port[50];
    ///int  mods; // todo create mods enum? or make this char[] type
    char user_name[50];
} server_info_t;


static struct
{
    const char *ServerName;
    const char *Address;
    const char *Port;
    const char *UserName;
    const char *Date;
    const char *p_open;
    const char *p_end;
} report_strings;

static const char *_servers_list_path;
static char *buff, *buff2;

int dap_chain_net_srv_vpn_cdb_server_list_init(const char * servers_list_path)
{
    _servers_list_path = strdup(servers_list_path);
    log_it(L_NOTICE,"Initialized Server List Module");
    return 0;
}

void dap_chain_net_srv_vpn_cdb_server_list_deinit(void)
{
    //config_destroy(&cfg);

    // free(buff); free(buff2);
}

//static inline int read_templates()
//{
//    int ret = 0;

//    config_init(&cfg);

//    if (!config_read_file(&cfg, my_config.report_template_file)) {
//        log_it(L_ERROR, "report_template_file not readed or not correct");
//        config_destroy(&cfg);
//        return ret;
//    }

//    if (!(config_lookup_string(&cfg, "report_paragraph_open", &report_strings.p_open) &&
//    config_lookup_string(&cfg, "report_paragraph_close", &report_strings.p_end) &&
//    config_lookup_string(&cfg, "report_server_address", &report_strings.Address)) ) {
//        log_it(L_ERROR, "Required template paramaters not avaible in templatefile");
//    } else {
//        config_lookup_string(&cfg, "report_server_name", &report_strings.ServerName);
//        config_lookup_string(&cfg, "report_port", &report_strings.Port);
//        config_lookup_string(&cfg, "report_user_name", &report_strings.UserName);
//        config_lookup_string(&cfg, "report_time", &report_strings.Date);
//        ret = 1;
//    }
//    return ret;
//}

///**
// * @brief time_string - make tine string
// * @return
// */
//static inline char *time_string()
//{
//    char *_time = (char*)malloc(strlen("9999-12-31 23:59:59")*sizeof(char)); //yep, be in pedantic =)
//    time_t t = time(0);
//    struct tm tm = *localtime(&t);
//    sprintf(_time, "%d-%d-%d %d:%d:%d", tm.tm_year + 1900, tm.tm_mon + 1,
//            tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
//    return _time;
//}

///**
// * @brief make_report - создает репорт файл для админа\
// * о недоступности сервера о какого-то пользователя
// * @param si
// */
//void make_report(const server_info_t *si)
//{
//    static bool config_ready;

//    if (!config_ready){
//        if(!my_config.report_template_file) {
//            log_it(L_ERROR, "report_template_file not readed");
//            return;
//        }
//        if ((config_ready = read_templates())) {
//            // if no call make_repor - we no allocate mem
//            // to internal data
//            buff  =  (char*)malloc(STR_SIZE*sizeof(char));
//            buff2 =  (char*)malloc(STR_SIZE*sizeof(char));
//            if (!buff && !buff2) {
//                log_it(L_ERROR, "can not allocate memmory");
//                free(buff);
//                free(buff2);
//                config_ready = 0;
//                config_destroy(&cfg);
//                return;
//            }
//        }
//    }

//    FILE *fp = fopen(REPORT_FILE_HEAD, "a+");
//    if (!fp) {
//        log_it(L_ERROR, "can not open file [%s]", REPORT_FILE_HEAD);
//        //free(buff); //free is not need here
//        //free(buff2);
//        return;
//    }

//    fseek(fp, 0L, SEEK_END);
//    if (ftell(fp))
//        ftruncate(fileno(fp), strlen(HTML_END));
//    else
//        fprintf(fp, HTML_HEAD);
//    fseek(fp, 0L, SEEK_SET);

//    sprintf(buff,"%s%s%s%s%s%s%s",report_strings.p_open,
//            report_strings.ServerName,
//            report_strings.Address,
//            report_strings.Port,
//            report_strings.UserName,
//            report_strings.Date,
//            report_strings.p_end);
//    strcpy(buff2, buff);

//    char *time = time_string();
//    sprintf(buff, buff2, si->name, si->address, si->port, si->user_name,
//            time);

//    fprintf(fp, buff);
//    fprintf(fp, HTML_END);

//    free(time);
//    fclose(fp);

//    return;
//}


void get_servers_list_http_proc(enc_http_delegate_t *dg, void *arg)
{
    arg = arg;
    FILE *fp;
    if (_servers_list_path) {
        fp = fopen(_servers_list_path, "r");
        if(!fp) {
            log_it(L_ERROR, "Can't open [%s] (serverlistfile)", _servers_list_path);
         }
    } else
        log_it(L_ERROR, "Can't open serverlist file", _servers_list_path);


    fseek(fp, 0L, SEEK_END);
    size_t fsize = ftell(fp);
    rewind(fp);

    char *buff = (char*)malloc(sizeof(char)*fsize);

    if (!buff) {
        log_it(L_ERROR, "can not allocate memmory");
        return;
    }
    fread(buff, fsize, 1, fp);

    if((dg->request)&&(strcmp(dg->action,"POST")==0)){
        if(dg->in_query==NULL){
            log_it(L_WARNING,"Empt action");
            dg->isOk=false;
        }else{
            if(strcmp(dg->in_query,"getall")==0 ){
                enc_http_reply_f(dg, buff);
            }
        }
    } else {
        log_it(L_ERROR, "Wrong auth request action '%s'",dg->action);
    }

    free(buff);
    fclose(fp);
}


//static void make_admin_report(enc_http_delegate_t *dg, void *arg)
//{
//    arg = arg;
//    //log_it (INFO, "izvlechennoe >%s<", dg->request_str);
//    if((dg->request)&&(strcmp(dg->action,"POST")==0)){
//        if(dg->in_query==NULL){
//            log_it(L_WARNING,"Empt action");
//            dg->isOk=false;
//        }else{
//            if(strcmp(dg->in_query,"badreport")==0 ){
//                enc_http_reply_f(dg, "OK" );
//                //parsing
//                {
//                    int end_str = strlen(dg->request_str);
//                    char buff[255];
//                    memset(buff,0,255);
//                    for(int i=0; i < end_str; ++i) {
//                        if (dg->request_str[i]== '&') {
//                            if (i+1 < end_str) {
//                                if (dg->request_str[i+1] == 'N') {
//                                    server_info_t si;
//                                    i+=2;
//                                    int field = 0;
//                                    int j = 0;
//                                    for (; i < end_str; ++i) {
//                                        if (dg->request_str[i] == '&') {
//                                            i++;
//                                            buff[j] = '\0';
//                                            switch (field) {
//                                               case 0: strcpy (si.address, buff); break;
//                                               case 1: strcpy (si.port, buff); break;
//                                               case 2: strcpy (si.user_name, buff); break;
//                                            }
//                                            memset(buff,0,255);
//                                            j = 0;
//                                            if (field == 2) {
//                                                make_report(&si);
//                                                i-=2;
//                                                break;
//                                            }
//                                            field++;
//                                        }
//                                        buff[j++] = dg->request_str[i];
//                                    }
//                                }
//                            }
//                        }
//                    }
//                }//parsing
//            }
//        }
//    } else {
//        log_it(L_ERROR, "Wrong auth request action '%s'",dg->action);
//    }

//}

void servers_list_http_proc(dap_http_simple_t *cl_st, void *arg)
{
    bool *isOk= (bool*)arg;
    enc_http_delegate_t *dg =enc_http_request_decode(cl_st);
    if ( dg != NULL) {
        dg->isOk = true;

        if (!strcmp(dg->url_path,"report")) {
            log_it(L_WARNING, "Report not supported at the moment");
          //  make_admin_report(dg, NULL);
        }

        if (!strcmp(dg->url_path,"update")) {
            get_servers_list_http_proc(dg, NULL);
        }

        *isOk = dg->isOk;

        enc_http_reply_encode(cl_st,dg);

        enc_http_delegate_delete(dg);
    }
}


void dap_chain_net_srv_vpn_cdb_server_list_add_proc(dap_http_t *sh, const char *url)
{
    dap_http_simple_proc_add(sh,url,1000000,servers_list_http_proc);
}
