Before compiling, create packages: `contrib/make_packages`

Commands::

    `make theming` to make a atlas out of a list of pngs

    `make apk` to make a apk

Building instructions for Ubuntu 16.04 x86_64::

  Download and extract crystax-ndk-10.3.2-linux-x86_64.tar.xz into ~/Downloads
  ```
  sudo add-apt-repository ppa:kivy-team/kivy-daily
  sudo dpkg --add-architecture i386
  sudo apt-get update
  sudo apt-get upgrade
  sudo apt-get install build-essential ccache git libncurses5:i386 libstdc++6:i386 libgtk2.0-0:i386 libpangox-1.0-0:i386 libpangoxft-1.0-0:i386 libidn11:i386 openjdk-8-jdk unzip zlib1g-dev zlib1g:i386
  sudo apt-get install python3-kivy python3-pip
  pip3 install -U --user pip cython
  pip3 install -U --user git+https://github.com/Electron-Cash/buildozer@ec3
  git clone -b ec3 --single-branch https://github.com/Electron-Cash/python-for-android.git ~/Downloads/python-for-android
  git clone https://github.com/Electron-Cash/Electron-Cash electron-cash
  cd electron-cash
  cd gui/kivy
  make theming
  cd ../..
  contrib/make_packages
  mv contrib/packages .
  contrib/make_apk
  ```
  a).It's normal if you get building errors for first time.
  Now you have to manually upgrade android sdk related tools, start SDK manager by:
  ```
  ~/.buildozer/android/platform/android-sdk-20/tools/android
  ```
  Once the gui pop up, install the updates and close it.
  Now comes the crazy part:
    You have to start SDK Manager and update and close it for several times until no updates avaiable.
  b).Install the latest version of Android SDK Build-tools 27.x.x, 19.1 is no good.
  c).Install the Android Support Repository.

  Now do the apk building again:
  ```
  contrib/make_apk
  ```

If something in included modules like kivy or any other module changes
then you need to rebuild the distribution. To do so:

  rm -rf .buildozer/
  rm -rf ~/.ccache/

