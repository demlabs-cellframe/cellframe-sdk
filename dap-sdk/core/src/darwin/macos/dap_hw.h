#ifndef DAP_HW_H
#define DAP_HW_H

#ifdef __cplusplus
extern "C" {
#endif

int _get_system_data_solid(char **repl, const char *a_cmd);
char *dap_get_motherboard_id();
char *dap_cpu_info();

#ifdef __cplusplus
}
#endif

#endif
