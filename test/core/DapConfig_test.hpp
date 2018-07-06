#pragma once
#include <QTest>
#include <QDebug>
#include "dap_config.h"

class DapConfigTest : public QObject {
    Q_OBJECT
private:
    const QByteArray testconfigName = "test_dap_config";
    const QByteArray configForTesting = "[db_options]\n"
                                        "db_type=mongoDb\n"
                                        "[server_options]\n"
                                        "timeout=1,5\n"
                                        "vpn_enable=true\n"
                                        "proxy_enable=false\n"
                                        "TTL_session_key=600\n"
                                        "str_arr=[vasya, petya, grisha, petushok@microsoft.com]\n"
                                        "int_arr=[1, 3, 5]\n";
    static constexpr size_t STR_ARR_LEN = 4;
    std::string m_strArrTestCase[STR_ARR_LEN] = {"vasya", "petya",
                                            "grisha", "petushok@microsoft.com"};

    static constexpr size_t INT_ARR_LEN = 3;
    int32_t m_intArrTestCase[INT_ARR_LEN] = {1, 3, 5};

    dap_config_t * m_cfg = nullptr;

    QFile configFile;
private slots:
    void initTestCase() {
        qDebug() << "initTestCase";
        configFile.setFileName(testconfigName + ".cfg");
        if(!configFile.open(QIODevice::WriteOnly))
        {
            qDebug() << "[DapConfigTest] Cant create testing config";
            QVERIFY(false);
        }
        configFile.write(configForTesting.data(), configForTesting.length());
        configFile.close();

        // init dir path for configs files
        dap_config_init(".");
        m_cfg = dap_config_open(testconfigName.data());
    }

    void configOpenFail() {
        // by default search in /opt/dap/etc path
        QVERIFY(dap_config_open("RandomNeverExistName") == NULL);
    }

    void getInt() {
        int32_t resultTTL = dap_config_get_item_int32(m_cfg, "server_options", "TTL_session_key");
        QCOMPARE(resultTTL, 600);
    }

    void getDobule() {
        /* if this test fail. Try change 1.5 to 1,5 in config. I think it's
         * some can be preferences system */
        double timeout = dap_config_get_item_double(m_cfg, "server_options", "timeout");
        QVERIFY(qFuzzyCompare(timeout, 1.5));
    }

    void getBool() {
        bool rBool = dap_config_get_item_bool(m_cfg, "server_options", "vpn_enable");
        QCOMPARE(rBool, true);
        rBool = dap_config_get_item_bool(m_cfg, "server_options", "proxy_enable");
        QCOMPARE(rBool, false);
    }

    void arrayStr() {
        uint16_t arraySize;
        char ** result_arr = dap_config_get_array_str(m_cfg, "server_options", "str_arr", &arraySize);

        QVERIFY(result_arr != NULL);
        QVERIFY(arraySize == STR_ARR_LEN);

        for(uint i = 0; i < arraySize; i++) {
            QVERIFY(::strcmp(result_arr[i], m_strArrTestCase[i].data()) == 0 );
        }
    }

    void arrayInt() {
        uint16_t arraySize;
        char ** result_arr = dap_config_get_array_str(m_cfg, "server_options", "int_arr", &arraySize);

        QVERIFY(result_arr != NULL);
        QVERIFY(arraySize == INT_ARR_LEN);

        for(uint i = 0; i < arraySize; i++) {
            //int value = ::atoi(result_arr[i]);
            QCOMPARE(::atoi(result_arr[i]), m_intArrTestCase[i]);
           // QVERIFY(::strcmp(result_arr[i], m_strArrTestCase[i].data()) == 0 );
        }
    }

    void cleanupTestCase() {
        qDebug() << "cleanupTestCase";
        configFile.remove();
        dap_config_close(m_cfg);
    }
};
