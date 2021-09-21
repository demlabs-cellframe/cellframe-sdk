#include "dap_sdk_init.h"

#define LOG_TAG "dap_sdk_init"

void *_dap_sdk_init_get_argument(dap_sdk_init_arg_t *a_arg, const char *a_param, void *a_default){
    for (int i=0; a_arg[i].param != NULL; i++){
        dap_sdk_init_arg_t l_arg = a_arg[i];
        if (dap_strcmp(l_arg.param, a_param) == 0){
            return l_arg.value;
        }
    }
    return  a_default;
}

int dap_sdk_init(dap_sdk_init_module_t *a_modules){
    for (int i=0; a_modules[i].module != NULL; i++)
    {
        dap_sdk_init_module_t l_module = a_modules[i];
        if(dap_strcmp(l_module.module, "common") == 0){
            char *log_path = _dap_sdk_init_get_argument(l_module.argv, "log_file", NULL);
            if (!log_path){
                return -1;
            }else{
                char *console_title = _dap_sdk_init_get_argument(l_module.argv, "console_title", NULL);
                if(!console_title){
                    return -1;
                }else{
                    char *log_dirpath = _dap_sdk_init_get_argument(l_module.argv, "log_dirpath", NULL);
                    if (!log_dirpath){
                        return -1;
                    }else{
                        int rc = dap_common_init(console_title, log_path, log_dirpath);
                        if (rc != 0){
                            return -2;
                        }
                        return 0;
                    }
                }
            }
        }
        if(dap_strcmp(l_module.module, "crypto") == 0){
            int rc = dap_enc_init();
            if (rc != 0 ){
                log_it(L_CRITICAL, "Can't initialize module crypto. Code: %i", rc);
                return -2;
            }
        }
    }
    return -5;
}
