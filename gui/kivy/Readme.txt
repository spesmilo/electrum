Before compiling, create packages: `contrib/make_packages`

Commands::

    `make theming` to make a atlas out of a list of pngs

    `make apk` to make a apk


If something in included modules like kivy or any other module changes
then you need to rebuild the distribution. To do so:

  rm -rf .buildozer/android/platform/python-for-android/dist


Notes:


To use internal storage, python-for-android must be patched with:

  git pull git@github.com:denys-duchier/python-for-android.git fix-recursive-delete


To fix the clipboard, pyjnius uses the handle_charsequence branch:

   export P4A_pyjnius_DIR=local_clone
