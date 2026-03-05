TEMPLATE = aux


linux: !android {
    CONFIG(debug, debug | release): sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target linux rwd -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCELLFRAME_NO_OPTIMIZATION=1
    CONFIG(release, debug | release): sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target linux release -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCELLFRAME_NO_OPTIMIZATION=1

}

win32 {
    
    CONFIG(release, debug | release): sdk_build.commands = "$$shell_path($$PWD/../cellframe-sdk/prod_build/build.sh)" --target windows release -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCELLFRAME_NO_OPTIMIZATION=1
    CONFIG(debug, debug | release): sdk_build.commands = "$$shell_path($$PWD/../cellframe-sdk/prod_build/build.sh)" --target windows rwd -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCELLFRAME_NO_OPTIMIZATION=1
    
}

android {
    CONFIG(release, debug | release): sdk_build.commands = export ANDROID_NDK_ROOT=$$NDK_ROOT && $$PWD/../cellframe-sdk/prod_build/build.sh -b $$QT_ARCH --target android release -DANDROID_PLATFORM=android-24 -DANDROID_ABI=$$QT_ARCH -DANDROID_NATIVE_API_LEVEL=24 -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DCELLFRAME_NO_OPTIMIZATION=1
    CONFIG(debug, debug | release): sdk_build.commands = export ANDROID_NDK_ROOT=$$NDK_ROOT && $$PWD/../cellframe-sdk/prod_build/build.sh -b $$QT_ARCH --target android rwd -DANDROID_PLATFORM=android-24 -DANDROID_ABI=$$QT_ARCH -DANDROID_NATIVE_API_LEVEL=24 -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DCELLFRAME_NO_OPTIMIZATION=1
}

mac {
    
    CONFIG(release, debug | release): sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target osx release -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCELLFRAME_NO_OPTIMIZATION=1
    CONFIG(debug, debug | release): sdk_build.commands = $$PWD/../cellframe-sdk/prod_build/build.sh --target osx rwd -DINSTALL_SDK=1 -DCMAKE_INSTALL_PREFIX=/ -DCELLFRAME_NO_OPTIMIZATION=1

}

QMAKE_EXTRA_TARGETS += sdk_build
PRE_TARGETDEPS = sdk_build

sdk_targets.path = /
sdk_targets.CONFIG += no_check_exist

INSTALLS += sdk_targets

