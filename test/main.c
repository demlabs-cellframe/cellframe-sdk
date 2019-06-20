#include "dap_common.h"

int main(void) {
    // switch off debug info from library
    dap_log_level_set(L_CRITICAL);
    return 0;
}
