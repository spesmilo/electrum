# Kivy GUI

The Kivy GUI is used with Electrum on Android devices.
To generate an APK file, follow these instructions.

Recommended env: Ubuntu 18.04

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
We need some functionality not in p4a master, so for the time being we have our own fork.

Something like this should work:

```sh
cd /opt
git clone https://github.com/kivy/python-for-android
cd python-for-android
git remote add sombernight https://github.com/SomberNight/python-for-android
git fetch --all
git checkout f74226666af69f9915afaee9ef9292db85a6c617
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

(from [buildozer docs](https://buildozer.readthedocs.io/en/latest/installation.html#targeting-android))
```sh
sudo pip install --upgrade cython==0.21
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install build-essential ccache git libncurses5:i386 libstdc++6:i386 libgtk2.0-0:i386 libpangox-1.0-0:i386 libpangoxft-1.0-0:i386 libidn11:i386 python2.7 python2.7-dev openjdk-8-jdk unzip zlib1g-dev zlib1g:i386
```

4.3 Download Android NDK
```sh
cd /opt
wget https://dl.google.com/android/repository/android-ndk-r14b-linux-x86_64.zip
unzip android-ndk-r14b-linux-x86_64.zip
```

## 5. Some more dependencies

```sh
python3 -m pip install colorama appdirs sh jinja2 cython==0.29
sudo apt-get install autotools-dev autoconf libtool pkg-config python3.7
```


## 6. Create the UI Atlas
In the `electrum/gui/kivy` directory of Electrum, run `make theming`.

## 7. Download Electrum dependencies
```sh
sudo contrib/make_packages
```

## 8. Try building the APK and fail

### 1. Try and fail:

```sh
contrib/make_apk
```

Symlink android tools:

```sh
ln -sf ~/.buildozer/android/platform/android-sdk-24/tools ~/.buildozer/android/platform/android-sdk-24/tools.save
```

### 2. Try and fail:

```sh
contrib/make_apk
```

During this build attempt, buildozer downloaded some tools,
e.g. those needed in the next step.

## 9. Update the Android SDK build tools

### Method 1: Using the GUI

  Start the Android SDK manager in GUI mode:
  
    ~/.buildozer/android/platform/android-sdk-24/tools/android

  Check the latest SDK available and install it
  ("Android SDK Tools" and "Android SDK Platform-tools").
  Close the SDK manager. Repeat until there is no newer version.
  
  Reopen the SDK manager, and install the latest build tools
  ("Android SDK Build-tools"), 28.0.3 at the time of writing.
  
  Install "Android 9">"SDK Platform".
  Install "Android Support Repository" from the SDK manager (under "Extras").

### Method 2: Using the command line:

  Repeat the following command until there is nothing to install:

    ~/.buildozer/android/platform/android-sdk-24/tools/android update sdk -u -t tools,platform-tools

  Install Build Tools, android API 19 and Android Support Library:

    ~/.buildozer/android/platform/android-sdk-24/tools/android update sdk -u -t build-tools-28.0.3,android-28,extra-android-m2repository

  (FIXME: build-tools is not getting installed?! use GUI for now.)

## 10. Build the APK

```sh
contrib/make_apk
```

# FAQ

## I changed something but I don't see any differences on the phone. What did I do wrong?
You probably need to clear the cache: `rm -rf .buildozer/android/platform/build/{build,dists}`
