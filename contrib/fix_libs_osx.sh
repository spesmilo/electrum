#!/bin/bash

cd dist/Electron-Cash.app/Contents/Resources 

if [ "$?" != "0" ]; then
	echo "Run setup-release.py py2app first." 
	exit 1
fi

if [ ! -e "qt_plugins" ]; then
	echo
	echo "Copying qt_plugins.."
	echo
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

