# Kivy GUI

The Kivy GUI is used with Electrum on Android devices. To generate an APK file, follow these instructions.

## 1. Install python-for-android (p4a)
p4a is used to package Electrum, Python, SDL and a bootstrap Java app into an APK file. 
We patched p4a to add some functionality we need for Electrum. Until those changes are
merged into p4a, you need to merge them locally (into the master branch):

1.1 [kivy/python-for-android#1217](https://github.com/kivy/python-for-android/pull/1217)

Something like this should work:

```sh
cd /opt
git clone https://github.com/kivy/python-for-android
cd python-for-android
git remote add agilewalker https://github.com/agilewalker/python-for-android
git fetch --all
git checkout 93759f36ba45c7bbe0456a4b3e6788622924cbac
git merge a2fb5ecbc09c4847adbcfd03c6b1ca62b3d09b8d
```

## 2. Install buildozer
2.1 Buildozer is a frontend to p4a. Luckily we don't need to patch it:

```sh
cd /opt
git clone https://github.com/kivy/buildozer
cd buildozer
sudo python3 setup.py install
```

2.2 Download the [Crystax NDK](https://www.crystax.net/en/download) manually.
Extract into `/opt/crystax-ndk-10.3.2`

## 3. Update the Android SDK build tools

### Method 1: Using the GUI

  Start the Android SDK manager in GUI mode:

      ~/.buildozer/android/platform/android-sdk-20/tools/android

  Check the latest SDK available and install it.
  Close the SDK manager.
  Reopen the SDK manager, scroll to the bottom and install the latest build tools (probably v27)
  Install "Android Support Library Repository" from the SDK manager.

### Method 2: Using the command line:

  Repeat the following command until there is nothing to install:

      ~/.buildozer/android/platform/android-sdk-20/tools/android update sdk -u -t tools,platform-tools

  Install Build Tools, android API 19 and Android Support Library:

      ~/.buildozer/android/platform/android-sdk-20/tools/android update sdk -u -t build-tools-27.0.3,android-19,extra-android-m2repository



## 5. Create the UI Atlas
In the `gui/kivy` directory of Electrum, run `make theming`.

## 6. Download Electrum dependencies
Run `contrib/make_packages`.

## 7. Build the APK
Run `contrib/make_apk`.

# FAQ
## Why do I get errors like `package me.dm7.barcodescanner.zxing does not exist` while compiling?
Update your Android build tools to version 27 like described above.

## Why do I get errors like  `(use -source 7 or higher to enable multi-catch statement)` while compiling?
Make sure that your p4a installation includes commit a3cc78a6d1a107cd3b6bd28db8b80f89e3ecddd2.
Also make sure you have recent SDK tools and platform-tools

## I changed something but I don't see any differences on the phone. What did I do wrong?
You probably need to clear the cache: `rm -rf .buildozer/android/platform/build/{build,dists}`
