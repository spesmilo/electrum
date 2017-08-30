Before compiling, create packages: `contrib/make_packages`

Commands::

    `make theming` to make a atlas out of a list of pngs

    `make apk` to make a apk


If something in included modules like kivy or any other module changes
then you need to rebuild the distribution. To do so:

  rm -rf .buildozer/android/platform/python-for-android/dist


how to build with ssl:

  rm -rf .buildozer/android/platform/build/
  ./contrib/make_apk
  pushd /opt/electrum/.buildozer/android/platform/build/build/libs_collections/Electrum/armeabi-v7a
  cp libssl1.0.2g.so /opt/crystax-ndk-10.3.2/sources/openssl/1.0.2g/libs/armeabi-v7a/libssl.so
  cp libcrypto1.0.2g.so /opt/crystax-ndk-10.3.2/sources/openssl/1.0.2g/libs/armeabi-v7a/libcrypto.so
  popd
  ./contrib/make_apk
