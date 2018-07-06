#include <QTest>
#include <QDebug>
#include "dap_common.h"

#define RUN_TESTS(TestObject) { \
    TestObject tc; \
    if(QTest::qExec(&tc)) \
        exit(1); }

/* comment this and add RUN_TESTS in main function
 * for run and debugging one testing class */
#define RUN_ALL_TESTS

#ifdef RUN_ALL_TESTS
#include "TestHeaders.hpp"
void run_all_tests() {
    RUN_TESTS(DapConfigTest)
}
#endif


int main(int argc, char *argv[])
{

    QCoreApplication app(argc, argv);
    app.setAttribute(Qt::AA_Use96Dpi, true);
    QTEST_SET_MAIN_SOURCE_PATH
#ifdef RUN_ALL_TESTS
    // switch off debug info from library
    set_log_level(L_CRITICAL);
    run_all_tests();
#endif
}
