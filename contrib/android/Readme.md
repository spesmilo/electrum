# Kivy GUI

The Kivy GUI is used with Electrum on Android devices.
To generate an APK file, follow these instructions.

## Android binary with Docker

✗ _This script does not produce reproducible output (yet!).
   Please help us remedy this._

This assumes an Ubuntu (x86_64) host, but it should not be too hard to adapt to another
similar system. The docker commands should be executed in the project's root
folder.

1. Install Docker

    ```
    $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    $ sudo apt-get update
    $ sudo apt-get install -y docker-ce
    ```

2. Build image

    ```
    $ sudo docker build -t electrum-android-builder-img contrib/android
    ```

3. Build locale files

    ```
    $ ./contrib/pull_locale
    ```

4. Prepare pure python dependencies

    ```
    $ ./contrib/make_packages
    ```

5. Build binaries

    ```
    $ mkdir --parents $PWD/.buildozer/.gradle
    $ sudo docker run -it --rm \
        --name electrum-android-builder-cont \
        -v $PWD:/home/user/wspace/electrum \
        -v $PWD/.buildozer/.gradle:/home/user/.gradle \
        -v ~/.keystore:/home/user/.keystore \
        --workdir /home/user/wspace/electrum \
        electrum-android-builder-img \
        ./contrib/android/make_apk
    ```
    This mounts the project dir inside the container,
    and so the modifications will affect it, e.g. `.buildozer` folder
    will be created.

5. The generated binary is in `./bin`.



## FAQ

### I changed something but I don't see any differences on the phone. What did I do wrong?
You probably need to clear the cache: `rm -rf .buildozer/android/platform/build-*/{build,dists}`


### How do I deploy on connected phone for quick testing?
Assuming `adb` is installed:
```
$ adb -d install -r bin/Electrum-*-arm64-v8a-debug.apk
$ adb shell monkey -p org.electrum.electrum 1
```


### How do I get an interactive shell inside docker?
```
$ sudo docker run -it --rm \
    -v $PWD:/home/user/wspace/electrum \
    -v $PWD/.buildozer/.gradle:/home/user/.gradle \
    --workdir /home/user/wspace/electrum \
    electrum-android-builder-img
```


### How do I get more verbose logs for the build?
See `log_level` in `buildozer.spec`


### How can I see logs at runtime?
This should work OK for most scenarios:
```
adb logcat | grep python
```
Better `grep` but fragile because of `cut`:
```
adb logcat | grep -F "`adb shell ps | grep org.electrum.electrum | cut -c14-19`"
```


### Kivy can be run directly on Linux Desktop. How?
Install Kivy.

Build atlas: `(cd contrib/android/; make theming)`

Run electrum with the `-g` switch: `electrum -g kivy`

### debug vs release build
If you just follow the instructions above, you will build the apk
in debug mode. The most notable difference is that the apk will be
signed using a debug keystore. If you are planning to upload
what you build to e.g. the Play Store, you should create your own
keystore, back it up safely, and run `./contrib/make_apk release`.

See e.g. [kivy wiki](https://github.com/kivy/kivy/wiki/Creating-a-Release-APK)
and [android dev docs](https://developer.android.com/studio/build/building-cmdline#sign_cmdline).

### Access datadir on Android from desktop (e.g. to copy wallet file)
Note that this only works for debug builds! Otherwise the security model
of Android does not let you access the internal storage of an app without root.
(See [this](https://stackoverflow.com/q/9017073))
```
$ adb shell
$ run-as org.electrum.electrum ls /data/data/org.electrum.electrum/files/data
$ run-as org.electrum.electrum cp /data/data/org.electrum.electrum/files/data/wallets/my_wallet /sdcard/some_path/my_wallet
```
