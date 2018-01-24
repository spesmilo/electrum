#!/bin/sh
sudo sh ./clean.sh
VERSION=$(cat lib/version.py \
  | grep ELECTRUM_VERSION \
  | sed "s/[',]//g" \
  | tr -d '[[:space:]]')
VERSION=${VERSION//ELECTRUM_VERSION=/}
echo "Creating package $VERSION"

sudo python3 setup.py sdist
echo "Creating python app using py2app"
sudo ARCHFLAGS="-arch i386 -arch x86_64" sudo python3 setup-release.py py2app --includes sip
echo "Creating python Electrum.app and .dmg"
sudo hdiutil create -fs HFS+ -volname "Electrum" -srcfolder dist/Electrum.app dist/electrum-$VERSION-macosx.dmg
echo "Done!"
