/*
 * Integration test harness for stream defragmentation tests.
 */
#include "dap_test.h"
#include "dap_common.h"

extern int test_stream_defrag_run(void);

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    return test_stream_defrag_run();
}
