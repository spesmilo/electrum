# Kivy GUI

The Kivy GUI is used with Electrum on Android devices. To generate an APK file, follow these instructions.

## 1. Install python-for-android (p4a)
p4a is used to package Electrum, Python, SDL and a bootstrap Java app into an APK file. 
We patched p4a to add some functionality we need for Electrum. Until those changes are
merged into p4a, you need to merge them locally (into the stable branch):

1. [kivy/python-for-android#1213](https://github.com/kivy/python-for-android/pull/1213)
2. [kivy/python-for-android#1217](https://github.com/kivy/python-for-android/pull/1217)

Something like this should work:

```sh
cd /opt
git clone https://github.com/kivy/python-for-android
cd python-for-android
git remote add agilewalker https://github.com/agilewalker/python-for-android
git remote add bauerj https://github.com/bauerj/python-for-android
git checkout stable
git fetch agilewalker
git merge agilewalker/master
git fetch bauerj
git merge bauerj/add-activity
```

## 2. Install buildozer
Buildozer is a frontend to p4a. Of course it needs to be patched too:

1. [kivy/buildozer#612](https://github.com/kivy/python-for-android/pull/1213)

```sh
cd /opt
git clone https://github.com/kivy/buildozer
cd buildozer
git remote add bauerj https://github.com/bauerj/buildozer
git fetch bauerj
git merge bauerj/add-activity
```

You also want to install it:

```sh
sudo python3 setup.py install
```

## 3. Update the Android SDK build tools
3.1 Start the Android SDK manager:

      ~/.buildozer/android/platform/android-sdk-20/tools/android
      
3.2 Check the latest SDK available and install it.

3.3 Close the SDK manager.

3.3 Reopen the SDK manager, scroll to the bottom and install the latest build tools (probably v27)

## 4. Install the Support Library Repository
Install "Android Support Library Repository" from the SDK manager.

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
Use the `stable` branch of python-for-android. 
[This commit](https://github.com/kivy/python-for-android/commit/3534a761b17040755accf941f898cc66b905e8db) in master is the culprit.

## I changed something but I don't see any differences on the phone. What did I do wrong?
You probably need to clear the cache: `rm -rf .buildozer/android/platform/build/{build,dists}`
