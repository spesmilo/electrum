[app]

# (str) Title of your application
title = Electrum

# (str) Package name
package.name = Electrum

# (str) Package domain (needed for android/ios packaging)
package.domain = org.electrum

# (str) Source code where the main.py live
source.dir = .

# (list) Source files to include (let empty to include all the files)
source.include_exts = py,png,jpg,qml,qmltypes,ttf,txt,gif,pem,mo,json,csv,so,svg

# (list) Source files to exclude (let empty to not exclude anything)
source.exclude_exts = spec

# (list) List of directory to exclude (let empty to not exclude anything)
source.exclude_dirs = bin, build, dist, contrib, env,
    tests,
    electrum/www,
    electrum/scripts,
    electrum/utils,
    electrum/gui/qt,
    electrum/plugins/payserver,
    packages/qdarkstyle,
    packages/qtpy,
    packages/bin,
    packages/share,
    packages/pkg_resources,
    packages/setuptools

# (list) List of exclusions using pattern matching
source.exclude_patterns = Makefile,setup*,
    # not reproducible:
    packages/aiohttp-*.dist-info/*,
    packages/frozenlist-*.dist-info/*

# (str) Application versioning (method 1)
version.regex = APK_VERSION = '(.*)'
version.filename = %(source.dir)s/electrum/version.py

# (str) Application versioning (method 2)
#version = 1.9.8

# (list) Application requirements
# note: versions and hashes are pinned in ./p4a_recipes/*
requirements =
    hostpython3,
    python3,
    android,
    openssl,
    plyer,
    libffi,
    libsecp256k1,
    cryptography,
    pyqt6sip,
    pyqt6,
    pillow,
    libzbar

# (str) Presplash of the application
presplash.filename = %(source.dir)s/electrum/gui/icons/electrum_presplash.png

# (str) Icon of the application
icon.filename = %(source.dir)s/electrum/gui/icons/android_electrum_icon_legacy.png
icon.adaptive_foreground.filename = %(source.dir)s/electrum/gui/icons/android_electrum_icon_foreground.png
icon.adaptive_background.filename = %(source.dir)s/electrum/gui/icons/android_electrum_icon_background.png

# (str) Supported orientation (one of landscape, portrait or all)
orientation = portrait

# (bool) Indicate if the application should be fullscreen or not
fullscreen = False


#
# Android specific
#

# (list) Permissions
android.permissions = INTERNET, CAMERA, WRITE_EXTERNAL_STORAGE

# (int) Android API to use  (compileSdkVersion)
# note: when changing, Dockerfile also needs to be changed to install corresponding build tools
android.api = 31

# (int) Android targetSdkVersion
android.target_sdk_version = 34

# (int) Minimum API required. You will need to set the android.ndk_api to be as low as this value.
android.minapi = 23

# (str) Android NDK version to use
android.ndk = 23b

# (int) Android NDK API to use (optional). This is the minimum API your app will support.
android.ndk_api = 23

# (bool) Use --private data storage (True) or --dir public storage (False)
#android.private_storage = True

# (str) Android NDK directory (if empty, it will be automatically downloaded.)
android.ndk_path = /opt/android/android-ndk

# (str) Android SDK directory (if empty, it will be automatically downloaded.)
android.sdk_path = /opt/android/android-sdk

# (str) ANT directory (if empty, it will be automatically downloaded.)
android.ant_path = /opt/android/apache-ant

# (bool) If True, then skip trying to update the Android sdk
# This can be useful to avoid excess Internet downloads or save time
# when an update is due and you just want to test/build your package
# note(ghost43): probably needed for reproducibility. versions pinned in Dockerfile.
android.skip_update = True

# (bool) If True, then automatically accept SDK license
# agreements. This is intended for automation only. If set to False,
# the default, you will be shown the license when first running
# buildozer.
android.accept_sdk_license = True

# (str) Android entry point, default is ok for Kivy-based app
#android.entrypoint = org.renpy.android.PythonActivity

# (list) List of Java .jar files to add to the libs so that pyjnius can access
# their classes. Don't add jars that you do not need, since extra jars can slow
# down the build process. Allows wildcards matching, for example:
# OUYA-ODK/libs/*.jar
#android.add_jars = foo.jar,bar.jar,path/to/more/*.jar
#android.add_jars = lib/android/zbar.jar

android.add_jars = .buildozer/android/platform/*/build/libs_collections/Electrum/jar/*.jar


# (list) List of Java files to add to the android project (can be java or a
# directory containing the files)
android.add_src = electrum/gui/qml/java_classes/

android.gradle_dependencies =
    com.android.support:support-compat:28.0.0,
    me.dm7.barcodescanner:zxing:1.9.8

android.add_activities = org.electrum.qr.SimpleScannerActivity

# (list) Put these files or directories in the apk res directory.
# The option may be used in three ways, the value may contain one or zero ':'
# Some examples:
# 1) A file to add to resources, legal resource names contain ['a-z','0-9','_']
# android.add_resources = my_icons/all-inclusive.png:drawable/all_inclusive.png
# 2) A directory, here  'legal_icons' must contain resources of one kind
# android.add_resources = legal_icons:drawable
# 3) A directory, here 'legal_resources' must contain one or more directories,
# each of a resource kind:  drawable, xml, etc...
# android.add_resources = legal_resources
android.add_resources = electrum/gui/qml/android_res/layout:layout

# (str) python-for-android branch to use, if not master, useful to try
# not yet merged features.
#android.branch = master

# (str) OUYA Console category. Should be one of GAME or APP
# If you leave this blank, OUYA support will not be enabled
#android.ouya.category = GAME

# (str) Filename of OUYA Console icon. It must be a 732x412 png image.
#android.ouya.icon.filename = %(source.dir)s/data/ouya_icon.png

# (str) XML file to include as an intent filters in <activity> tag
android.manifest.intent_filters = contrib/android/bitcoin_intent.xml

# (str) launchMode to set for the main activity
android.manifest.launch_mode = singleTask

# (list) Android additional libraries to copy into libs/armeabi
#android.add_libs_armeabi = lib/android/*.so

# (bool) Indicate whether the screen should stay on
# Don't forget to add the WAKE_LOCK permission if you set this to True
#android.wakelock = False

# (str) The Android arch to build for, choices: armeabi-v7a, arm64-v8a, x86, x86_64
# note: can be overwritten by APP_ANDROID_ARCH env var
#android.arch = armeabi-v7a

# (int) overrides automatic versionCode computation (used in build.gradle)
# this is not the same as app version and should only be edited if you know what you're doing
# android.numeric_version = 1

# (list) Android application meta-data to set (key=value format)
#android.meta_data =

# (list) Android library project to add (will be added in the
# project.properties automatically.)
#android.library_references =

android.whitelist = lib-dynload/_csv.so

# (bool) enables Android auto backup feature (Android API >=23)
android.allow_backup = False

# (str) The format used to package the app for release mode (aab or apk or aar).
android.release_artifact = apk

# (str) The format used to package the app for debug mode (apk or aar).
android.debug_artifact = apk

#
# Python for android (p4a) specific
#

# (str) python-for-android git clone directory (if empty, it will be automatically cloned from github)
p4a.source_dir = /opt/python-for-android

# (str) The directory in which python-for-android should look for your own build recipes (if any)
p4a.local_recipes = %(source.dir)s/contrib/android/p4a_recipes/

# (str) Filename to the hook for p4a
#p4a.hook =

# (str) Bootstrap to use for android builds
p4a.bootstrap = qt6

# (int) port number to specify an explicit --port= p4a argument (eg for bootstrap flask)
#p4a.port =


#
# iOS specific
#

# (str) Name of the certificate to use for signing the debug version
# Get a list of available identities: buildozer ios list_identities
#ios.codesign.debug = "iPhone Developer: <lastname> <firstname> (<hexstring>)"

# (str) Name of the certificate to use for signing the release version
#ios.codesign.release = %(ios.codesign.debug)s



[buildozer]

# (int) Log level (0 = error only, 1 = info, 2 = debug (with command output))
log_level = 2

# (str) Path to build output (i.e. .apk, .ipa) storage
bin_dir = ./dist


# -----------------------------------------------------------------------------
# List as sections
#
# You can define all the "list" as [section:key].
# Each line will be considered as a option to the list.
# Let's take [app] / source.exclude_patterns.
# Instead of doing:
#
#     [app]
#     source.exclude_patterns = license,data/audio/*.wav,data/images/original/*
#
# This can be translated into:
#
#     [app:source.exclude_patterns]
#     license
#     data/audio/*.wav
#     data/images/original/*
#

# -----------------------------------------------------------------------------
# Profiles
#
# You can extend section / key with a profile
# For example, you want to deploy a demo version of your application without
# HD content. You could first change the title to add "(demo)" in the name
# and extend the excluded directories to remove the HD content.
#
#     [app@demo]
#     title = My Application (demo)
#
#     [app:source.exclude_patterns@demo]
#     images/hd/*
#
# Then, invoke the command line with the "demo" profile:
#
#     buildozer --profile demo android debug
