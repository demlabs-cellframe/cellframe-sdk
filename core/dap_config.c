#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "uthash.h"
#include "file_utils.h"
#include "dap_common.h"
#include "dap_config.h"

#define LOG_TAG "dap_config"

/**
 * @brief The dap_config_item struct
 */
typedef struct dap_config_item{
    char name[64];
    struct dap_config_item * childs;
    struct dap_config_item * item_next;
    union{
        char *data_str;
        uint8_t data_uint8;
        bool data_bool;
        double data_double;
        int32_t data_int32;
        struct {
            char **data_str_array;
            uint16_t array_length;
        };
    };
    bool is_array;
    UT_hash_handle hh;
} dap_config_item_t;


typedef struct dap_config_internal
{
    dap_config_item_t * item_root;
} dap_config_internal_t;
#define DAP_CONFIG_INTERNAL(a) ( (dap_config_internal_t* ) a->_internal )

#define MAX_CONFIG_PATH 256
static char s_configs_path[MAX_CONFIG_PATH] = "/opt/dap/etc";


/**
 * @brief dap_config_init Initialization settings
 * @param[in] a_configs_path If NULL path is set to default
 * @return
 */
int dap_config_init(const char * a_configs_path)
{
    if( a_configs_path ) {
#ifdef _WIN32
        // Check up under Windows, in Linux is not required
        if(!valid_ascii_symbols(a_configs_path)) {
            log_it(L_ERROR, "Supported only ASCII symbols for directory path");
            return -1;
        }
#endif
        if(dir_test(a_configs_path) || !mkdir_with_parents(a_configs_path)) {
            strcpy(s_configs_path, a_configs_path);
            return 0;
        }
    }
    return -1;
}

/**
 * @brief dap_config_deinit Deinitialize settings
 */
void dap_config_deinit()
{

}


/**
 * @brief get_array_length Function parse string and return array length
 * @param[in] value
 * @details internal function parse string and return array length
 * @return
 */
static uint16_t get_array_length(const char* str) {
    uint16_t array_length = 1; // by default if not find ','
    while (*str) {
        if (*str == ',')
            array_length++;
        str++;
    }
    return array_length;
}
/**
 * @brief dap_config_open Open the configuration settings
 * @param[in] a_name Configuration name
 * @return dap_config_t Configuration
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
                                        // log_it(L_DEBUG,"Config section '%s'",l_section_name);

                                        dap_config_item_t * l_item_section = DAP_NEW_Z(dap_config_item_t);
                                        strncpy(l_item_section->name,l_section_name,sizeof(l_item_section->name)-1);
                                        l_item_section->item_next = l_config_internal->item_root;
                                        l_config_internal->item_root = l_item_section;
                                        free(l_section_name);

                                        l_section_current = l_item_section;
                                    }else{ // key-value line
                                        //log_it(L_DEBUG,"Read line '%s'",l_line);
                                        char l_param_name[sizeof(l_section_current->name)];
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
                                            for(int j=(int)l_param_value_size-1; j>=0; j--){
                                                if( (l_param_value[j] ==' ') || (l_param_value[j] =='\t') ){
                                                    l_param_value[j] = '\0';
                                                }else{
                                                    break;
                                                }
                                            }
                                        }
                                    //    log_it(L_DEBUG,"  Param '%s' = '%s'", l_param_name, l_param_value);
                                        if (l_section_current){

                                            if (l_param_value[0] == '[') {
                                                if(l_param_value[1] == ']') {
                                                    log_it(L_WARNING, "Empty array!");
                                                    continue;
                                                }

                                                // delete '[' and ']'
                                                char* values = l_param_value + 1;
                                                values[l_param_value_size-2] = 0;

                                                dap_config_item_t * l_item = DAP_NEW_Z(dap_config_item_t);

                                                strncpy(l_item->name,l_param_name,sizeof(l_item->name));
                                                l_item->item_next = l_section_current->childs;
                                                l_item->is_array = true;
                                                l_section_current->childs = l_item;
                                                l_item->array_length = get_array_length(l_param_value);
                                                l_item->data_str_array = (char**) malloc (sizeof(char*) * l_item->array_length);
                                                // parsing items in array
                                                int j = 0;
                                                char *token = strtok(values, ",");
                                                while(token) {

                                                    // trim token whitespace
                                                    if (isspace(token[0]))
                                                        token = token + 1;
                                                    if (isspace(token[strlen(token) - 1])
                                                            || token[strlen(token) - 1] == ']' /* last item in array */)
                                                        token[strlen(token) - 1] = 0;

                                                    l_item->data_str_array[j] = strdup(token);

                                                    token = strtok(NULL, ",");
                                                    j++;
                                                }

                                            } else {
                                                dap_config_item_t * l_item = DAP_NEW_Z(dap_config_item_t);

                                                strncpy(l_item->name,l_param_name,sizeof(l_item->name));
                                                l_item->item_next = l_section_current->childs;
                                                l_item->data_str = strdup (l_param_value);

                                                l_section_current->childs = l_item;
                                            }
                                        }else{
                                            log_it(L_ERROR,"Can't add param to a tree without current section");
                                        }

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
            fclose(f);
        }else{
            log_it(L_ERROR,"Can't open config file '%s' (%s)",l_config_path,strerror(errno));
        }
        DAP_DELETE(l_config_path);
    }else{
        log_it(L_ERROR,"Config name is NULL");
    }
    return ret;
}

/**
 * @brief dap_config_close Closing the configuration
 * @param[in] a_config Configuration
 */
void dap_config_close(dap_config_t * a_config)
{
    dap_config_item_t * l_item = DAP_CONFIG_INTERNAL(a_config)->item_root ;
    while(l_item) {
        dap_config_item_t * l_item_child = l_item->childs;
        DAP_CONFIG_INTERNAL(a_config)->item_root = l_item->item_next;

        while(l_item_child) {
            l_item->childs = l_item_child->item_next;
            if(l_item_child->is_array) {
                for(int i = 0; i< l_item_child->array_length; i++)
                    free(l_item_child->data_str_array[i]);
                free(l_item_child->data_str_array);
            } else if (l_item_child->data_str) {
                DAP_DELETE(l_item_child->data_str);
            }
            DAP_DELETE(l_item_child);
            l_item_child = l_item->childs;
        }

        if(l_item->data_str) {
            DAP_DELETE(l_item->data_str);
        }
        DAP_DELETE(l_item);
        l_item = DAP_CONFIG_INTERNAL(a_config)->item_root;
    }

    free(a_config->_internal);
    free(a_config);

}

/**
 * @brief dap_config_get_item_int32 Getting a configuration item as a int32
 * @param[in] a_config
 * @param[in] a_section_path
 * @param[in] a_item_name
 * @return
 */
int32_t dap_config_get_item_int32(dap_config_t * a_config, const char * a_section_path, const char * a_item_name)
{
    return atoi(dap_config_get_item_str(a_config,a_section_path,a_item_name));
}

/**
 * @brief dap_config_get_item_int32_default Getting a configuration item as a int32
 * @param[in] a_config Configuration
 * @param[in] a_section_path Path
 * @param[in] a_item_name setting
 * @param[in] a_default
 * @return
 */
int32_t dap_config_get_item_int32_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, int32_t a_default)
{
    const char * l_str_ret = dap_config_get_item_str(a_config,a_section_path,a_item_name);
    return l_str_ret?atoi(l_str_ret):a_default;
}


/**
 * @brief dap_config_get_item Get the configuration as a item
 * @param[in] a_config Configuration
 * @param[in] a_section_path Path
 * @param[in] a_item_name setting
 * @return
 */
static dap_config_item_t * dap_config_get_item(dap_config_t * a_config, const char * a_section_path, const char * a_item_name)
{
    dap_config_item_t * l_item_section = DAP_CONFIG_INTERNAL(a_config)->item_root ;
    while(l_item_section){
        if (strcmp(l_item_section->name,a_section_path)==0){
            dap_config_item_t * l_item = l_item_section->childs;
            while (l_item){
                if (strcmp(l_item->name,a_item_name)==0){
                    return l_item;
                }
                l_item = l_item->item_next;
            }
        }
        l_item_section = l_item_section->item_next;
    }
    return NULL;
}


/**
 * @brief dap_config_get_item_str Getting a configuration item as a string
 * @param[in] a_config Configuration
 * @param[in] a_section_path Path
 * @param[in] a_item_name setting
 * @return
 */
const char * dap_config_get_item_str(dap_config_t * a_config, const char * a_section_path, const char * a_item_name)
{
    dap_config_item_t * item = dap_config_get_item(a_config, a_section_path, a_item_name);
    if (item == NULL)
        return NULL;
    return item->data_str;
}


/**
 * @brief dap_config_get_array_str Getting an array of configuration items as a string
 * @param[in] a_config Configuration
 * @param[in] a_section_path Path
 * @param[in] a_item_name setting
 * @return
 */
char** dap_config_get_array_str(dap_config_t * a_config, const char * a_section_path,
                                const char * a_item_name, uint16_t * array_length) {
    dap_config_item_t * item = dap_config_get_item(a_config, a_section_path, a_item_name);
    if (item == NULL)
        return NULL;
    if (array_length != NULL)
        *array_length = item->array_length;
    return item->data_str_array;
}


/**
 * @brief dap_config_get_item_str_default Getting an array of configuration items as a string
 * @param[in] a_config Configuration
 * @param[in] a_section_path Path
 * @param[in] a_item_name setting
 * @param[in] a_value_default Default
 * @return
 */
const char * dap_config_get_item_str_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, const char * a_value_default)
{
    dap_config_item_t * l_item_section = DAP_CONFIG_INTERNAL(a_config)->item_root ;
    while(l_item_section){
        if (strcmp(l_item_section->name,a_section_path)==0){
            dap_config_item_t * l_item = l_item_section->childs;
            while (l_item){
                if (strcmp(l_item->name,a_item_name)==0){
                    return l_item->data_str;
                }
                l_item = l_item->item_next;
            }
        }
        l_item_section = l_item_section->item_next;
    }
    return a_value_default;
}

/**
 * @brief dap_config_get_item_bool Getting a configuration item as a boolean
 * @param[in] a_config Configuration
 * @param[in] a_section_path Path
 * @param[in] a_item_name Setting
 * @return
 */
bool dap_config_get_item_bool(dap_config_t * a_config, const char * a_section_path, const char * a_item_name)
{
    return strcmp(dap_config_get_item_str(a_config,a_section_path,a_item_name),"true") == 0;
}


/**
 * @brief dap_config_get_item_bool_default Getting a configuration item as a boolean
 * @param[in] a_config Configuration
 * @param[in] a_section_path Path
 * @param[in] a_item_name Setting
 * @param[in] a_default Default
 * @return
 */
bool dap_config_get_item_bool_default(dap_config_t * a_config, const char * a_section_path,
                                      const char * a_item_name, bool a_default)
{
    return strcmp(dap_config_get_item_str_default(a_config,a_section_path,a_item_name,
                                                  a_default?"true":"false"),"true") == 0;
}

/**
 * @brief dap_config_get_item_double Getting a configuration item as a floating-point value
 * @param[in] a_config Configuration
 * @param[in] a_section_path Path
 * @param[in] a_item_name Setting
 * @return
 */
double dap_config_get_item_double(dap_config_t * a_config, const char * a_section_path, const char * a_item_name)
{
    return atof(dap_config_get_item_str(a_config,a_section_path,a_item_name));
}

/**
 * @brief dap_config_get_item_double Getting a configuration item as a floating-point value
 * @param[in] a_config Configuration
 * @param[in] a_section_path Path
 * @param[in] a_item_name Setting
 * @param[in] a_default Defailt
 * @return
 */
double dap_config_get_item_double_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, double a_default)
{
    const char * l_str_ret = dap_config_get_item_str(a_config,a_section_path,a_item_name);
    return l_str_ret?atof(l_str_ret):a_default;
}

