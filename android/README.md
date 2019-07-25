The Android app can be built on any OS supported by Android Studio. However, the following
automated process is available for Linux x86-64:

If necessary, install Docker using the [instructions on its
website](https://docs.docker.com/install/#supported-platforms).

Copy your release key to `keystore.jks` in this directory. It must contain a key with the
following configuration:

    keyAlias "key0"
    keyPassword "android"
    storePassword "android"

Run `build.sh`. The APK will be generated in `release` in this directory.

Between it builds it may be helpful to clear out the docker images with:

`docker container prune && docker image prune`
