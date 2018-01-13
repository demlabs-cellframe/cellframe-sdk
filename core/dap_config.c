#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "dap_common.h"
#include "dap_config.h"

#define LOG_TAG "dap_config"

typedef struct dap_config_internal
{
    dap_config_item_t * root;
} dap_config_internal_t;
#define DAP_CONFIG_INTERNAL(a) ( (dap_config_internal_t* ) a->_internal )

char *s_configs_path = "/opt/dap/etc";




/**
 * @brief dap_config_init
 * @param a_configs_path If NULL path is set to default
 * @return
 */
int dap_config_init(const char * a_configs_path)
{
    if( a_configs_path ){
        s_configs_path = strdup(a_configs_path);
        char cmd[1024];
        snprintf(cmd,sizeof(cmd),"test -d %s || mkdir -p %s",a_configs_path,a_configs_path);
        system(cmd);
    }
}

/**
 * @brief dap_config_deinit
 */
void dap_config_deinit()
{

}

/**
 * @brief dap_config_open
 * @param a_name
 * @return
 */
dap_config_t * dap_config_open(const char * a_name)
{
    dap_config_t * ret = NULL;
    if ( a_name ){
        log_it(L_DEBUG,"Looking for config name %s...",a_name);
        size_t l_config_path_size_max = strlen(a_name)+6+strlen(s_configs_path);
        char *l_config_path = DAP_NEW_SIZE(char,l_config_path_size_max);
        snprintf(l_config_path,l_config_path_size_max, "%s/%s.cfg",s_configs_path,a_name);
        FILE * f = fopen(l_config_path,"r");
        if ( f ){
            log_it(L_DEBUG,"Opened config %s",a_name);
            ret = DAP_NEW_Z(dap_config_t);
            dap_config_internal_t * l_config_internal = DAP_NEW_Z(dap_config_internal_t);
            ret->_internal = l_config_internal;

            char buf[1024];
            size_t l_global_offset=0;
            size_t l_buf_size=0;
            size_t l_buf_pos_line_start=0;
            size_t l_buf_pos_line_end=0;
            dap_config_item_t * l_section_current = NULL ;
            bool l_is_space_now = false;
            while ( feof(f)==0){ // Break on lines
                size_t i;
                l_global_offset +=  (l_buf_size = fread(buf,1,sizeof(buf),f) );
                for (i=0; i< l_buf_size; i++){
                    if( (buf[i] == '\r') || (buf[i] == '\n' ) ){
                        if( ! l_is_space_now){
                            l_buf_pos_line_end = i;
                            l_is_space_now = true;
                            //if(l_buf_pos_line_end)
                            //    l_buf_pos_line_end--;
                            if(l_buf_pos_line_end != l_buf_pos_line_start ){ // Line detected
                                char *l_line = NULL;
                                size_t l_line_length = 0;
                                size_t j;

                                // Trimming spaces and skip the line if commented
                                for ( j = l_buf_pos_line_start; j < l_buf_pos_line_end; j++ ){
                                    if ( buf[j] == '#' )
                                        break;
                                    if (buf[j] != ' ' ){
                                        l_line_length = (l_buf_pos_line_end - j);
                                        break;
                                    }
                                }
                                if( l_line_length ){
                                    l_line = DAP_NEW_SIZE(char,l_line_length+1);
                                    memcpy(l_line,buf+j,l_line_length);
                                    l_line[l_line_length] = 0;

                                    // Process trimmed line
                                    if( (l_line[0] == '[' ) && (l_line[l_line_length-1] == ']' ) ){ // Section detected
                                        //log_it(L_DEBUG, "Raw line '%s'",l_line);
                                        char * l_section_name = strdup(l_line+1);
                                        size_t l_section_name_length = (l_line_length - 2);
                                        l_section_name[l_section_name_length]='\0';
                                        log_it(L_DEBUG,"Config section '%s'",l_section_name);

                                        dap_config_item_t * l_item = DAP_NEW_Z(dap_config_item_t);
                                        l_item->header.name = l_section_name;
                                        l_item->header.next = l_config_internal->root;
                                        l_config_internal->root = l_item;

                                        l_section_current = l_item;
                                    }else{ // key-value line
                                        //log_it(L_DEBUG,"Read line '%s'",l_line);
                                        char l_param_name[256];
                                        size_t l_param_name_size=0;
                                        size_t l_param_value_size=0;
                                        char l_param_value[1024];
                                        l_param_name[0] = 0;
                                        l_param_value[0] = 0;
                                        for ( j = 0; j < l_line_length; j++ ){ // Parse param name
                                            if ( ( l_line[j] == ' ' )|| ( l_line[j] == '=' ) ||( l_line[j] == '\t' ) ){ // Param name
                                                l_param_name_size = j;
                                                if (l_param_name_size > (sizeof(l_param_name) -1) ){
                                                    l_param_name_size = (sizeof(l_param_name) - 1 );
                                                    log_it(L_WARNING,"Too long param name in config, %u is more than %u maximum",
                                                           j,sizeof(l_param_name) -1);
                                                }
                                                strncpy(l_param_name,l_line,j);
                                                l_param_name[j] = 0;
                                                break;
                                            }

                                        }

                                        for (; j < l_line_length; j++ ){ // Find beginning of param value
                                            if ( ( l_line[j] != '\t' ) && ( l_line[j] != ' ' ) && ( l_line[j] != '=' ) ){
                                                break;
                                            }
                                        }
                                        l_param_value_size = l_line_length - j;
                                        if (l_param_value_size ){
                                            if (l_param_value_size > (sizeof(l_param_value) -1) ){
                                                l_param_value_size = (sizeof(l_param_value) - 1 );
                                                log_it(L_WARNING,"Too long param value in config, %u is more than %u maximum",
                                                       l_line_length - j,sizeof(l_param_value) -1);
                                            }
                                            strncpy(l_param_value,l_line +j, l_param_value_size);
                                            l_param_value[l_param_value_size] = '\0';
                                            for(j=l_param_value_size-1; j>=0; j--){
                                                if( (l_param_value[j] ==' ') || (l_param_value[j] =='\t') ){
                                                    l_param_value[j] = '\0';
                                                }else{
                                                    break;
                                                }
                                            }
                                        }
                                        log_it(L_DEBUG,"  Param '%s' = '%s'", l_param_name, l_param_value);
                                    }
                                    DAP_DELETE(l_line);
                                }
                            }
                        }
                        continue;
                    }else{
                        if (l_is_space_now){
                            l_is_space_now = false;
                            l_buf_pos_line_start = i;
                        }
                    }
                }
            }
        }else{
            log_it(L_ERROR,"Can't open config file '%s' (%s)",l_config_path,strerror(errno));
        }

    }else{
        log_it(L_ERROR,"Config name is NULL");
    }
    return ret;
}

/**
 * @brief dap_config_close
 * @param a_config
 */
void dap_config_close(dap_config_t * a_config)
{

}

/**
 * @brief dap_config_get_item_int32
 * @param a_config
 * @param a_section_path
 * @param a_item_name
 * @return
 */
int32_t dap_config_get_item_int32(dap_config_t * a_config, const char * a_section_path, const char * a_item_name)
{

}

/**
 * @brief dap_config_get_item_str
 * @param a_config
 * @param a_section_path
 * @param a_item_name
 * @return
 */
const char * dap_config_get_item_str(dap_config_t * a_config, const char * a_section_path, const char * a_item_name)
{
    return NULL;
}

/**
 * @brief dap_config_get_item_bool
 * @param a_config
 * @param a_section_path
 * @param a_item_name
 * @return
 */
bool dap_config_get_item_bool(dap_config_t * a_config, const char * a_section_path, const char * a_item_name)
{

}

/**
 * @brief dap_config_get_item_double
 * @param a_config
 * @param a_section_path
 * @param a_item_name
 * @return
 */
double dap_config_get_item_double(dap_config_t * a_config, const char * a_section_path, const char * a_item_name)
{

}

