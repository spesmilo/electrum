# Kivy GUI

The Kivy GUI is used with Electrum on Android devices.
To generate an APK file, follow these instructions.

## Android binary with Docker

✓ _These binaries should be reproducible, meaning you should be able to generate
   binaries that match the official releases._

This assumes an Ubuntu (x86_64) host, but it should not be too hard to adapt to another
similar system.

1. Install Docker

    See `contrib/docker_notes.md`.

2. Build binaries

    The build script takes a few arguments. To see syntax, run it without providing any:
    ```
    $ ./build.sh
    ```
    For development, consider e.g. `$ ./build.sh kivy arm64-v8a debug`

    If you want reproducibility, try instead e.g.:
    ```
    $ ELECBUILD_COMMIT=HEAD ELECBUILD_NOCACHE=1 ./build.sh kivy all release-unsigned
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
keystore, back it up safely, and run `./contrib/make_apk.sh release`.

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
