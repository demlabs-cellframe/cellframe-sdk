TEMPLATE = aux

CONFIG(debug, debug|release) {
  target_name = debug
}
CONFIG(release, debug|release) {
  target_name = release
}

linux: !android {
    sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target linux $$target_name -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/
}

win32 {
    contains(QMAKE_HOST.os, "Windows") {
        sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.bat
    }
    else {
        sdk_build.commands = "$$shell_path($$PWD/../cellframe-sdk/prod_build/build.sh)" --target windows $$target_name -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/
    }
}

android {
    for (AABI, ANDROID_ABIS) {
        message("Requested ABI: $$AABI")
        sdk_build_$${AABI}.commands += $$PWD/../cellframe-sdk/prod_build/build.sh -b $$AABI --target android $$target_name -DANDROID_PLATFORM=android-21 -DANDROID_ABI=$$AABI -DANDROID_NATIVE_API_LEVEL=29 -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON
    }
}

mac {

    sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target osx $$target_name -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/
}

QMAKE_EXTRA_TARGETS += sdk_build
PRE_TARGETDEPS = sdk_build

android {
    for (AABI, ANDROID_ABIS) {

        QMAKE_EXTRA_TARGETS += sdk_build_$${AABI}
        PRE_TARGETDEPS += sdk_build_$${AABI}
    }
}

sdk_targets.path = /
sdk_targets.CONFIG += no_check_exist

INSTALLS += sdk_targets

