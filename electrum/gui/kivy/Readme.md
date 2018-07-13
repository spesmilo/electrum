# Kivy GUI

The Kivy GUI is used with Electrum on Android devices. To generate an APK file, follow these instructions.

## 1. Preliminaries

Make sure the current user can write `/opt` (e.g. `sudo chown username: /opt`).

We assume that you already got Electrum to run from source on this machine,
hence have e.g. `git`, `python3-pip` and `python3-setuptools`.

## 2. Install kivy

Install kivy for python3 as described [here](https://kivy.org/docs/installation/installation-linux.html).
So for example:
```sh
sudo add-apt-repository ppa:kivy-team/kivy
sudo apt-get install python3-kivy
```


## 3. Install python-for-android (p4a)
p4a is used to package Electrum, Python, SDL and a bootstrap Java app into an APK file. 
We patched p4a to add some functionality we need for Electrum. Until those changes are
merged into p4a, you need to merge them locally (into the master branch):

3.1 [kivy/python-for-android#1217](https://github.com/kivy/python-for-android/pull/1217)

Something like this should work:

```sh
cd /opt
git clone https://github.com/kivy/python-for-android
cd python-for-android
git remote add agilewalker https://github.com/agilewalker/python-for-android
git remote add sombernight https://github.com/SomberNight/python-for-android
git fetch --all
git checkout 93759f36ba45c7bbe0456a4b3e6788622924cbac
git cherry-pick a2fb5ecbc09c4847adbcfd03c6b1ca62b3d09b8d  # openssl-fix
git cherry-pick a0ef2007bc60ed642fbd8b61937995dbed0ddd24  # disable backups
```

## 4. Install buildozer
4.1 Buildozer is a frontend to p4a. Luckily we don't need to patch it:

```sh
cd /opt
git clone https://github.com/kivy/buildozer
cd buildozer
sudo python3 setup.py install
```

4.2 Install additional dependencies:
```sh
sudo apt-get install python-pip
```
and the ones listed
[here](https://buildozer.readthedocs.io/en/latest/installation.html#targeting-android).

You will also need
```sh
python3 -m pip install colorama appdirs sh jinja2
```


4.3 Download the [Crystax NDK](https://www.crystax.net/en/download) manually.
Extract into `/opt/crystax-ndk-10.3.2`


## 5. Create the UI Atlas
In the `gui/kivy` directory of Electrum, run `make theming`.

## 6. Download Electrum dependencies
```sh
sudo contrib/make_packages
```

## 7. Try building the APK and fail

```sh
contrib/make_apk
```

During this build attempt, buildozer downloaded some tools,
e.g. those needed in the next step.

## 8. Update the Android SDK build tools

### Method 1: Using the GUI

  Start the Android SDK manager in GUI mode:
  
    ~/.buildozer/android/platform/android-sdk-20/tools/android

  Check the latest SDK available and install it
  ("Android SDK Tools" and "Android SDK Platform-tools").
  Close the SDK manager. Repeat until there is no newer version.
  
  Reopen the SDK manager, and install the latest build tools
  ("Android SDK Build-tools"), 27.0.3 at the time of writing.
  
  Install "Android Support Repository" from the SDK manager (under "Extras").

### Method 2: Using the command line:

  Repeat the following command until there is nothing to install:

    ~/.buildozer/android/platform/android-sdk-20/tools/android update sdk -u -t tools,platform-tools

  Install Build Tools, android API 19 and Android Support Library:

    ~/.buildozer/android/platform/android-sdk-20/tools/android update sdk -u -t build-tools-27.0.3,android-19,extra-android-m2repository


## 9. Build the APK

```sh
contrib/make_apk
```

# FAQ
## Why do I get errors like `package me.dm7.barcodescanner.zxing does not exist` while compiling?
Update your Android build tools to version 27 like described above.

## Why do I get errors like  `(use -source 7 or higher to enable multi-catch statement)` while compiling?
Make sure that your p4a installation includes commit a3cc78a6d1a107cd3b6bd28db8b80f89e3ecddd2.
Also make sure you have recent SDK tools and platform-tools

## I changed something but I don't see any differences on the phone. What did I do wrong?
You probably need to clear the cache: `rm -rf .buildozer/android/platform/build/{build,dists}`
