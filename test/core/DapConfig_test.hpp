#pragma once
#include <QTest>
#include "dap_config.h"

class DapConfigTest : public QObject {
    Q_OBJECT
private:
    // helper functions
private slots:
    void dapConfigOpenFail() {
        QVERIFY(dap_config_open("RandomNeverExistName") == NULL);
    }
};
