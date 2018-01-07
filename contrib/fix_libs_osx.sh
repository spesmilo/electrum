#!/bin/bash

cd dist/Electron-Cash.app/Contents/Resources 

if [ "$?" != "0" ]; then
	echo "Run setup-release.py py2app first." 
	exit 1
fi

pyver=""
pydotver=""

if [ -e "lib/python36.zip" ]; then
	pyver="36"
	pydotver="3.6"
elif [ -e "lib/python35.zip" ]; then
	pyver="35"
	pydotver="3.5"
else
	echo 'Cannot determine python version used -- only 3.5 and 3.6 are supported at this time by this script. Sorry.'
	exit 1
fi

zfile="lib/python${pyver}.zip"
ldir="python${pydotver}"

if [ ! -d "$zfile" ]; then
	echo
	echo "Doing some magic to compensate for broken py2app stuff..."
	echo
	mv -v "${zfile}" "lib/z.zip"
	mkdir -v "$zfile"
	cd "$zfile"
	unzip ../z.zip && rm -f ../z.zip
	if [ "$?" != "0" ]; then
		echo "Something went wrong"
		exit 1
	fi
	[ -e electroncash_plugins ] && mv -vf electroncash_plugins electroncash_plugins.bak
	ln -svf ../"${ldir}"/plugins electroncash_plugins
	[ -e electroncash ] && mv -vf electroncash electroncash.bak
	ln -svf ../"${ldir}"/lib electroncash
	[ -e electroncash_gui ] && mv -vf electroncash_gui electroncash_gui.bak
	ln -svf ../"${ldir}"/gui electroncash_gui
	cd ../../
	if [ ! -d "${zfile}" ] || [ ! -e "${zfile}/electroncash_plugins" ] || [ ! -e "${zfile}/electroncash" ] || [ ! -e "${zfile}/electroncash_gui" ]; then
		echo 'Something went wrong... File a github issue at http://www.github.com/fyookball/electrum.'
		exit 1
	fi
fi

if [ ! -e "qt_plugins" ]; then
	echo
	echo "Copying qt_plugins.."
	echo

	if [ ! -d /opt/local/libexec/qt5/plugins ]; then
		echo "Qt5 not found -- this script requires it be installed in /opt/local as per MacPorts. Sorry."
		exit 1
	fi

	mkdir qt_plugins
	cp -fpvR /opt/local/libexec/qt5/plugins/* qt_plugins/
	echo
	echo "Removing unneeded libs.."
	echo
	rm -fvr qt_plugins/Py*Qt5
	rm -vf qt_plugins/platforms/libqminimal.dylib qt_plugins/platforms/libqoffscreen.dylib
fi

otool -l qt_plugins/platforms/libqcocoa.dylib  | grep -q '@executable_path/../Frameworks'

if [ "$?" != "0" ]; then
	echo
	echo "Adding rpath to libs..."
	echo
	find qt_plugins -type f -name \*.dylib -exec install_name_tool -add_rpath '@executable_path/../Frameworks' {} \; -print
fi

echo
echo "Rewriting library link paths..."
echo

for a in qt_plugins/*/*.dylib; do 
	libs=`otool -L "$a" | cut -f 2  | cut -f 1 -d ' '`
	for l in $libs; do
		ending=""
		if [ x"${l:0:27}" == x"/opt/local/libexec/qt5/lib/" ]; then
			ending="${l:27}"
		elif [ x"${l:0:15}" == x"/opt/local/lib/" ]; then
			ending="${l:15}"
		fi
		if [ -n "$ending" ]; then
			newpath="@rpath/${ending}"
			echo "${a}: Rewriting $l to $newpath"
			install_name_tool -change "$l" "$newpath" "$a"
		fi
	done
done

echo
echo 'Done!'

