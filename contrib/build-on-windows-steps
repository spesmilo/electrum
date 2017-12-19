build-on-windows-steps
===================

* Install Python3.6
* Install msgfmt(maybe you can install msysgit, which includes msgfmt)
* cd to projects' parent directory
* git clone https://github.com/ecdsa/pyinstaller.git
* git fetch origin fix_2952:fix_2952 && git checkout fix_2952
* cd to pyinstaller directory
* cd to projects' parent directory 
* git clone https://github.com/spesmilo/electrum-icons
* git clone https://github.com/spesmilo/electrum-locale
* cd to electrum-locale/locale/zh-CN
* mkdir LC_MESSAGES
* msgfmt --output-file=./LC_MESSAGES/electrum.mo ./electrum.po
* cd to projects' parent directory
* cp -r electrum-locale/locale electrum/lib/
* cp electrum-icons/icons_rc.py electrum/gui/qt/
* cd to the electrum directory
* pip install ./contrib/requirements.txt
* pip install trezor btchip-python
* python setup.py install
* cp contrib/build-wine/* .
* modify file ./deterministic.spec, change the path of the project's directory in it
* pyinstaller.exe --noconfirm --ascii --name $NAME_ROOT-$VERSION -w deterministic.spec
* if you want to make nsis setup program, run `makensis.exe" /DPRODUCT_VERSION=$VERSION electrum.nsi`
* You can find the result-program.exe in the `dist` directory
