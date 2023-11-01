TEMPLATE = aux


linux {
    sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target linux release -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/
}

win32 {
    contains(QMAKE_HOST.os, "Windows") {
        sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.bat
    }
    else {
        sdk_build.commands = "$$shell_path($$PWD/../cellframe-sdk/prod_build/build.sh)" --target windows release -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/
    }
}

android {
    sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target android release -DANDROID_PLATFORM=android-21 -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/
}

mac {
    sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target osx release -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/
}


QMAKE_EXTRA_TARGETS += sdk_build
PRE_TARGETDEPS = sdk_build

sdk_targets.path = /
sdk_targets.CONFIG += no_check_exist

INSTALLS += sdk_targets

