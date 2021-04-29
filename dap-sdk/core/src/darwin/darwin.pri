macos {
    include(macos/macos.pri)
}
QMAKE_CXXFLAGS += -Wno-deprecated-copy
INCLUDEPATH += $$PWD
