#pragma once
#include <QTest>
#include <QDebug>
#include "dap_config.h"

class DapConfigTest : public QObject {
    Q_OBJECT
private:
    const QByteArray testconfigName = "test_dap_config.cfg";
    const QByteArray configForTesting ="db_type=\"mongoDb\";\n"
                                    "db_name=\"dapDb\";\n"
                                    "db_path=\"mongodb://localhost/db\";\n"
                                    "listen_address=\"127.0.0.1\";\n"
                                    "TTL_session_key=600;\n"
                                    "vpn_addr=\"10.0.0.0\";\n";
    QFile configFile;

    // helper functions
private slots:
    void initTestCase() {
        qDebug() << "initTestCase";
        configFile.setFileName(testconfigName);
        if(!configFile.open(QIODevice::WriteOnly))
        {
            qDebug() << "[DapConfigTest] Cant create testing config";
            QVERIFY(false);
        }
        configFile.write(configForTesting.data(), configForTesting.length());
        configFile.close();
    }

    void dapConfigOpenFail() {
        // by default search in /opt/dap/etc path
        QVERIFY(dap_config_open("RandomNeverExistName") == NULL);
    }

//    void initAndOpenConfig() {
//        // init current dir path for config
//        dap_config_init(".");
//        dap_config_t * file = dap_config_open(testconfigName.data());
//       // dap_config_close(file);
//    }

    void cleanupTestCase() {
        qDebug() << "cleanupTestCase";
        configFile.remove();
    }
};
