#!/bin/sh
sudo sh ./clean.sh
VERSION=$(python3 -c "from lib import version; print(version.ELECTRUM_VERSION)")
VERSION=${VERSION//ELECTRUM_VERSION=/}
echo "Creating package $VERSION"

echo "brew install"
brew bundle

echo "pip install"
pip3 install -r requirements.txt

echo "building icons"
pyrcc5 icons.qrc -o gui/qt/icons_rc.py

echo "Compile the protobuf description file"
protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

echo "compiling translations"
./config/make_locale

echo "Creating package $VERSION"
sudo python3 setup.py sdist

echo "Creating python app using py2app"
sudo ARCHFLAGS="-arch i386 -arch x86_64" sudo python3 setup-release.py py2app --includes sip

echo "Creating python Electrum.app and .dmg"
sudo hdiutil create -fs HFS+ -volname "Electrum" -srcfolder dist/Electrum.app dist/electrum-$VERSION-macosx.dmg

echo "Done!"
