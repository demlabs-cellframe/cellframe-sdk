TEMPLATE = aux


linux: !android {
    CONFIG(debug, debug | release): sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target linux rwd -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCELLFRAME_NO_OPTIMIZATION=1
    CONFIG(release, debug | release): sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target linux release -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCELLFRAME_NO_OPTIMIZATION=1

}

win32 {
    
    CONFIG(release, debug | release): sdk_build.commands = "$$shell_path($$PWD/../cellframe-sdk/prod_build/build.sh)" --target windows release -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/
    CONFIG(debug, debug | release): sdk_build.commands = "$$shell_path($$PWD/../cellframe-sdk/prod_build/build.sh)" --target windows rwd -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/
    
}

android {
    for (AABI, ANDROID_ABIS) {
        message("Requested ABI: $$AABI")
        CONFIG(release, debug | release): sdk_build_$${AABI}.commands += $$PWD/../cellframe-sdk/prod_build/build.sh -b $$AABI --target android release -DANDROID_PLATFORM=android-21 -DANDROID_ABI=$$AABI -DANDROID_NATIVE_API_LEVEL=29 -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON
        CONFIG(debug, debug | release): sdk_build_$${AABI}.commands += $$PWD/../cellframe-sdk/prod_build/build.sh -b $$AABI --target android release -DANDROID_PLATFORM=android-21 -DANDROID_ABI=$$AABI -DANDROID_NATIVE_API_LEVEL=29 -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON

    }
}

mac {
    
    CONFIG(release, debug | release): sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target osx release -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/
    CONFIG(debug, debug | release): sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target osx rwd -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/

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

