# Qml GUI

The Qml GUI is used with Electrum on Android devices, since Electrum 4.4.
To generate an APK file, follow these instructions.

(note: older versions of Electrum for Android used the "kivy" GUI)

## Android binary with Docker

✓ _These binaries should be reproducible, meaning you should be able to generate
   binaries that match the official releases._

This assumes an Ubuntu (x86_64) host, but it should not be too hard to adapt to another
similar system.

1. Install Docker

    See [`contrib/docker_notes.md`](../docker_notes.md).

    (worth reading even if you already have docker)

2. Build binaries

    The build script takes a few arguments. To see syntax, run it without providing any:
    ```
    $ ./build.sh
    ```
    For development, consider e.g. `$ ./build.sh qml arm64-v8a debug`

    If you want reproducibility, try instead e.g.:
    ```
    $ ELECBUILD_COMMIT=HEAD ./build.sh qml all release-unsigned
    ```

3. The generated binary is in `./dist`.


## Verifying reproducibility and comparing against official binary

Every user can verify that the official binary was created from the source code in this
repository.

1. Build your own binary as described above.
   Make sure you don't build in `debug` mode,
   instead use either of `release` or `release-unsigned`.
   If you build in `release` mode, the apk will be signed, which requires a keystore
   that you need to create manually (see source of `make_apk.sh` for an example).
2. Note that the binaries are not going to be byte-for-byte identical, as the official
   release is signed by a keystore that only the project maintainers have.
   You can use the `apkdiff.py` python script (written by the Signal developers) to compare
   the two binaries.
    ```
    $ python3 contrib/android/apkdiff.py Electrum_apk_that_you_built.apk Electrum_apk_official_release.apk
    ```
   This should output `APKs match!`.


## FAQ

### I changed something but I don't see any differences on the phone. What did I do wrong?
You probably need to clear the cache: `rm -rf .buildozer/android/platform/build-*/{build,dists}`


### How do I deploy on connected phone for quick testing?
Assuming `adb` is installed:
```
$ adb -d install -r dist/Electrum-*-arm64-v8a-debug.apk
$ adb shell monkey -p org.electrum.electrum 1
```


### How do I get an interactive shell inside docker?
```
$ docker run -it --rm \
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


### The Qml GUI can be run directly on Linux Desktop. How?
Install requirements:
```
python3 -m pip install "pyqt6==6.5.2" "Pillow>=8.4"
```

Run electrum with the `-g` switch: `electrum -g qml`

Notes:

- pyqt ~6.4 would work best, as the gui has not yet been adapted to styling changes in 6.5
- However, pyqt6 as distributed on PyPI does not include a required module (PyQt6.QtQml) until 6.5
- Installing these deps from your OS package manager should also work,
  except many don't distribute pyqt6 yet.
  For pyqt5 on debian-based distros, this used to look like this:
  ```
  sudo apt-get install python3-pyqt5 python3-pyqt5.qtquick python3-pyqt5.qtmultimedia
  sudo apt-get install python3-pil
  sudo apt-get install qml-module-qtquick-controls2 qml-module-qtquick-layouts \
      qml-module-qtquick-window2 qml-module-qtmultimedia \
      libqt5multimedia5-plugins qml-module-qt-labs-folderlistmodel
  ```


### debug vs release build
If you just follow the instructions above, you will build the apk
in debug mode. The most notable difference is that the apk will be
signed using a debug keystore. If you are planning to upload
what you build to e.g. the Play Store, you should create your own
keystore, back it up safely, and run `./contrib/make_apk.sh release`.

See e.g. [kivy wiki](https://github.com/kivy/kivy/wiki/Creating-a-Release-APK)
and [android dev docs](https://developer.android.com/studio/build/building-cmdline#sign_cmdline).

### Access datadir on Android from desktop (e.g. to copy wallet file)
Note that this only works for debug builds! Otherwise the security model
of Android does not let you access the internal storage of an app without root.
(See [this](https://stackoverflow.com/q/9017073))
To pull a file:
```
$ adb shell
adb$ run-as org.electrum.electrum ls /data/data/org.electrum.electrum/files/data
adb$ exit
$ adb exec-out run-as org.electrum.electrum cat /data/data/org.electrum.electrum/files/data/wallets/my_wallet > my_wallet
```
To push a file:
```
$ adb push ~/wspace/tmp/my_wallet /data/local/tmp
$ adb shell
adb$ ls -la /data/local/tmp
adb$ run-as org.electrum.testnet.electrum cp /data/local/tmp/my_wallet /data/data/org.electrum.testnet.electrum/files/data/testnet/wallets/
adb$ rm /data/local/tmp/my_wallet
```

Or use Android Studio: "Device File Explorer", which can download/upload data directly from device (via adb).

### How to investigate diff between binaries if reproducibility fails?
```
cd dist/
unzip Electrum-*.apk1 -d apk1
mkdir apk1/assets/private_mp3/
tar -xzvf apk1/assets/private.mp3 --directory apk1/assets/private_mp3/

unzip Electrum-*.apk2 -d apk2
mkdir apk2/assets/private_mp3/
tar -xzvf apk2/assets/private.mp3 --directory apk2/assets/private_mp3/

sudo chown --recursive "$(id -u -n)" apk1/ apk2/
chmod -R +Xr  apk1/ apk2/
$(cd apk1; find -type f -exec sha256sum '{}' \; > ./../sha256sum1)
$(cd apk2; find -type f -exec sha256sum '{}' \; > ./../sha256sum2)
diff sha256sum1 sha256sum2 > d
cat d
```

### How to install apks built by the CI on my phone?

The CI (Cirrus) builds apks on most git commits.
See e.g. [here](https://github.com/spesmilo/electrum/runs/9272252577).
The task name should start with "Android build".
Click "View more details on Cirrus CI" to get to cirrus' website, and search for "Artifacts".
The apk is built in `debug` mode, and is signed using an ephemeral RSA key.

For tech demo purposes, you can directly install this apk on your phone.
However, if you already have electrum installed on your phone, Android's TOFU signing model
will not let you upgrade that to the CI apk due to mismatching signing keys. As the CI key
is ephemeral, it is not even possible to upgrade from an older CI apk to a newer CI apk.

However, it is possible to resign the apk manually with one's own key, using
e.g. [`apksigner`](https://developer.android.com/studio/command-line/apksigner),
mutating the apk in place, after which it should be possible to upgrade:
```
apksigner sign --ks ~/wspace/electrum/contrib/android/android_debug.keystore Electrum-*-arm64-v8a-debug.apk
```
