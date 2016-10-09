Before compiling, create packages: `contrib/make_packages`

Commands::

    `make theming` to make a atlas out of a list of pngs

    `make apk` to make a apk


If something in included modules like kivy or any other module changes
then you need to rebuild the distribution. To do so:

  rm -rf .buildozer/android/platform/python-for-android/dist

