#!/bin/bash

. ./common.sh

/usr/bin/env python3 --version | grep -q " 3.[6789]"
if [ "$?" != "0" ]; then
	if /usr/bin/env python3 --version; then
		echo "WARNING:: Creating the Briefcase-based Xcode project for iOS requires Python 3.6+."
		echo "We will proceed anyway -- but if you get errors, try switching to Python 3.6+."
	else
		echo "ERROR: Python3+ is required"
		exit 1
	fi
fi

/usr/bin/env python3 -m pip show setuptools > /dev/null
if [ "$?" != "0" ]; then
	echo "ERROR: Please install setupdools like so: sudo python3 -m pip install briefcase"
	exit 2
fi

/usr/bin/env python3 -m pip show briefcase > /dev/null
if [ "$?" != "0" ]; then
	echo "ERROR: Please install briefcase like so: sudo python3 -m pip install briefcase"
	exit 3
fi

/usr/bin/env python3 -m pip show cookiecutter > /dev/null
if [ "$?" != "0" ]; then
	echo "ERROR: Please install cookiecutter like so: sudo python3 -m pip install cookiecutter"
	exit 4
fi

/usr/bin/env python3 -m pip show pbxproj > /dev/null
if [ "$?" != "0" ]; then
	echo "ERROR: Please install pbxproj like so: sudo python3 -m pip install pbxproj"
	exit 5
fi

if [ -d iOS ]; then
	echo "Warning: 'iOS' directory exists. All modifications will be lost if you continue."
	echo "Continue? [y/N]?"
	read reply
	if [ "$reply" != "y" ]; then
		echo "Fair enough. Exiting..."
		exit 0
	fi
	echo "Cleaning up old iOS dir..."
	rm -fr iOS
fi

if [ -d ${compact_name}/electroncash ]; then
	echo "Deleting old ${compact_name}/electroncash..."
	rm -fr ${compact_name}/electroncash
fi

echo "Pulling 'electroncash' libs into project from ../electroncash ..."
if [ ! -d ../electroncash/locale ]; then
	(cd .. && contrib/make_locale && cd ios)
	if [ "$?" != 0 ]; then
		echo ERROR: Could not build locales
		exit 1
	fi
fi
cp -fpR ../electroncash ${compact_name}/electroncash
echo "Removing electroncash/tests..."
rm -fr ${compact_name}/electroncash/tests
find ${compact_name} -name \*.pyc -exec rm -f {} \;

echo ""
echo "Building Briefcase-Based iOS Project..."
echo ""

python3 setup.py ios
if [ "$?" != 0 ]; then
	echo "An error occurred running setup.py"
	exit 4
fi

# No longer needed: they fixed the bug.  But leaving it here in case bug comes back!
#cd iOS && ln -s . Support ; cd .. # Fixup for broken Briefcase template.. :/

infoplist="iOS/${compact_name}/${compact_name}-Info.plist"
if [ -f "${infoplist}" ]; then
	echo ""
	echo "Adding custom keys to ${infoplist} ..."
	echo ""
	plutil -insert "NSAppTransportSecurity" -xml '<dict><key>NSAllowsArbitraryLoads</key><true/></dict>' -- ${infoplist}
	if [ "$?" != "0" ]; then
		echo "Encountered error adding custom key NSAppTransportSecurity to plist!"
		exit 1
	fi
	#plutil -insert "UIBackgroundModes" -xml '<array><string>fetch</string></array>' -- ${infoplist}
	#if [ "$?" != "0" ]; then
	#	echo "Encountered error adding custom key UIBackgroundModes to plist!"
	#	exit 1
	#fi
	longver=`git describe --tags`
	if [ -n "$longver" ]; then
		shortver=`echo "$longver" | cut -f 1 -d -`
		plutil -replace "CFBundleVersion" -string "$longver" -- ${infoplist} && plutil -replace "CFBundleShortVersionString" -string "$shortver" -- ${infoplist}
		if [ "$?" != "0" ]; then
			echo "Encountered error adding custom keys to plist!"
			exit 1
		fi
	fi
	# UILaunchStoryboardName -- this is required to get proper iOS screen sizes due to iOS being quirky AF
	if [ -e "Resources/LaunchScreen.storyboard" ]; then
		plutil -insert "UILaunchStoryboardName" -string "LaunchScreen" -- ${infoplist}
		if [ "$?" != "0" ]; then
			echo "Encountered an error adding LaunchScreen to Info.plist!"
			exit 1
		fi
	fi
	# Camera Usage key -- required!
	plutil -insert "NSCameraUsageDescription" -string "The camera is needed to scan QR codes" -- ${infoplist}

	# Stuff related to being able to open .txn and .txt files (open transaction from context menu in other apps)
	plutil -insert "CFBundleDocumentTypes" -xml '<array><dict><key>CFBundleTypeIconFiles</key><array/><key>CFBundleTypeName</key><string>Transaction</string><key>LSItemContentTypes</key><array><string>public.plain-text</string></array><key>LSHandlerRank</key><string>Owner</string></dict></array>' -- ${infoplist}
	plutil -insert "UTExportedTypeDeclarations" -xml '<array><dict><key>UTTypeConformsTo</key><array><string>public.plain-text</string></array><key>UTTypeDescription</key><string>Transaction</string><key>UTTypeIdentifier</key><string>com.c3-soft.ElectronCash.txn</string><key>UTTypeSize320IconFile</key><string>signed@2x</string><key>UTTypeSize64IconFile</key><string>signed</string><key>UTTypeTagSpecification</key><dict><key>public.filename-extension</key><array><string>txn</string><string>txt</string></array></dict></dict></array>' -- ${infoplist}
	plutil -insert "UTImportedTypeDeclarations" -xml '<array><dict><key>UTTypeConformsTo</key><array><string>public.plain-text</string></array><key>UTTypeDescription</key><string>Transaction</string><key>UTTypeIdentifier</key><string>com.c3-soft.ElectronCash.txn</string><key>UTTypeSize320IconFile</key><string>signed@2x</string><key>UTTypeSize64IconFile</key><string>signed</string><key>UTTypeTagSpecification</key><dict><key>public.filename-extension</key><array><string>txn</string><string>txt</string></array></dict></dict></array>' -- ${infoplist}
	plutil -insert 'CFBundleURLTypes' -xml '<array><dict><key>CFBundleTypeRole</key><string>Viewer</string><key>CFBundleURLName</key><string>bitcoincash</string><key>CFBundleURLSchemes</key><array><string>bitcoincash</string></array></dict></array>' -- ${infoplist}
	plutil -replace 'UIRequiresFullScreen' -bool NO -- ${infoplist}
	plutil -insert 'NSFaceIDUsageDescription' -string 'FaceID is used for wallet authentication' -- ${infoplist}
	plutil -insert 'ITSAppUsesNonExemptEncryption' -bool NO -- ${infoplist}

	# Un-comment the below to enforce only portrait orientation mode on iPHone
	#plutil -replace "UISupportedInterfaceOrientations" -xml '<array><string>UIInterfaceOrientationPortrait</string></array>' -- ${infoplist}
	# Because we are using FullScreen = NO, we must support all interface orientations
	plutil -replace 'UISupportedInterfaceOrientations' -xml '<array><string>UIInterfaceOrientationPortrait</string><string>UIInterfaceOrientationLandscapeLeft</string><string>UIInterfaceOrientationLandscapeRight</string><string>UIInterfaceOrientationPortraitUpsideDown</string></array>' -- ${infoplist}
	plutil -insert 'UIViewControllerBasedStatusBarAppearance' -bool NO -- ${infoplist}
	plutil -insert 'UIStatusBarStyle' -string 'UIStatusBarStyleLightContent' -- ${infoplist}
	plutil -insert 'NSPhotoLibraryAddUsageDescription' -string 'Required to save QR images to the photo library' -- ${infoplist}
	plutil -insert 'NSPhotoLibraryUsageDescription' -string 'Required to save QR images to the photo library' -- ${infoplist}
	plutil -insert 'LSSupportsOpeningDocumentsInPlace' -bool NO -- ${infoplist}

	# We don't support dark mode, so we must force light mode even if phone is in dark mode on iOS 13+
	plutil -insert  'UIUserInterfaceStyle' -string 'Light' -- ${infoplist}
fi

if [ -d overrides/ ]; then
	echo ""
	echo "Applying overrides..."
	echo ""
	(cd overrides && cp -fpvR * ../iOS/ && cd ..)
fi

stupid_launch_image_grr="iOS/${compact_name}/Images.xcassets/LaunchImage.launchimage"
if [ -d "${stupid_launch_image_grr}" ]; then
	echo ""
	echo "Removing deprecated LaunchImage stuff..."
	echo ""
	rm -fvr "${stupid_launch_image_grr}"
fi

patches=patches/*.patch
if [ -n "$patches" ]; then
	echo ""
	echo "Applying patches..."
	echo ""
	for p in $patches; do
		[ -e $p ] && patch -p 1 < $p
	done
fi

# Get latest rubicon with all the patches from Github
echo ""
echo "Updating rubicon-objc to latest from forked repository on github..."
echo ""
[ -e scratch ] && rm -fr scratch
mkdir -v scratch || exit 1
cd scratch || exit 1
git clone http://www.github.com/cculianu/rubicon-objc
gitexit="$?"
cd rubicon-objc
git checkout "fe054117056d33059a5db8addbc14e8535f08d3b^{commit}" # from branch send_super_fix
gitexit2="$?"
cd ..
cd ..
[ "$gitexit" != "0" -o "$gitexit2" != 0 ] && echo '*** Error grabbing the latest rubicon off of github' && exit 1
rm -fr iOS/app_packages/rubicon/objc
cp -fpvr scratch/rubicon-objc/rubicon/objc iOS/app_packages/rubicon/
[ "$?" != "0" ] && echo '*** Error copying rubicon files' && exit 1
rm -fr scratch

xcode_file="${xcode_target}.xcodeproj/project.pbxproj"
echo ""
echo "Mogrifying Xcode .pbxproj file to use iOS 10.0 deployment target..."
echo ""
sed  -E -i original1 's/(.*)IPHONEOS_DEPLOYMENT_TARGET = [0-9.]+(.*)/\1IPHONEOS_DEPLOYMENT_TARGET = 10.0\2/g' "iOS/${xcode_file}" && \
  sed  -n -i original2 '/ASSETCATALOG_COMPILER_LAUNCHIMAGE_NAME/!p' "iOS/${xcode_file}"
if [ "$?" != 0 ]; then
	echo "Error modifying Xcode project file iOS/$xcode_file... aborting."
	exit 1
else
	echo ".pbxproj mogrifid ok."
fi

echo ""
echo "Adding HEADER_SEARCH_PATHS to Xcode .pbxproj..."
echo ""
python3 -m pbxproj flag -t "${xcode_target}" iOS/"${xcode_file}" -- HEADER_SEARCH_PATHS '"$(SDK_DIR)"/usr/include/libxml2'
if [ "$?" != 0 ]; then
	echo "Error adding libxml2 to HEADER_SEARCH_PATHS... aborting."
	exit 1
fi

resources=Resources/*
if [ -n "$resources" ]; then
	echo ""
	echo "Adding Resurces/ and CustomCode/ to project..."
	echo ""
	cp -fRav Resources CustomCode iOS/
	(cd iOS && python3 -m pbxproj folder -t "${xcode_target}" -r -i "${xcode_file}" Resources)
	if [ "$?" != 0 ]; then
		echo "Error adding Resources to iOS/$xcode_file... aborting."
		exit 1
	fi
	(cd iOS && python3 -m pbxproj folder -t "${xcode_target}" -r "${xcode_file}" CustomCode)
	if [ "$?" != 0 ]; then
		echo "Error adding CustomCode to iOS/$xcode_file... aborting."
		exit 1
	fi
fi

so_crap=`find iOS/app_packages -iname \*.so -print`
if [ -n "$so_crap" ]; then
	echo ""
	echo "Deleting .so files in app_packages since they don't work anyway on iOS..."
	echo ""
	for a in $so_crap; do
		rm -vf $a
	done
fi

echo ""
echo "Modifying main.m to include PYTHONIOENCODING=UTF-8..."
echo ""
main_m="iOS/${compact_name}/main.m"
if cat $main_m | sed -e '1 s/putenv/putenv("PYTHONIOENCODING=UTF-8"); putenv/; t' -e '1,// s//putenv("PYTHONIOENCODING=UTF-8"); putenv/' | sed -e 's/PYTHONOPTIMIZE=1/PYTHONOPTIMIZE=/;' > ${main_m}.new; then
	mv -fv ${main_m}.new $main_m
else
	echo "** WARNING: Failed to modify main.m to include PYTHONIOENCODING=UTF-8"
fi

echo ""
echo "Copying google protobuf paymentrequests.proto to app lib dir..."
echo ""
cp -fva ${compact_name}/electroncash/*.proto iOS/app/${compact_name}/electroncash
if [ "$?" != "0" ]; then
	echo "** WARNING: Failed to copy google protobuf .proto file to app lib dir!"
fi

# Clean up no-longer-needed electroncash/ dir that is outside of Xcode project
rm -fr ${compact_name}/electroncash/*

# Can add this back when it works uniformly without issues
# /usr/bin/env ruby update_project.rb

echo ''
echo '**************************************************************************'
echo '*                                                                        *'
echo '*   Operation Complete. An Xcode project has been generated in "iOS/"    *'
echo '*                                                                        *'
echo '**************************************************************************'
echo ''
echo '  IMPORTANT!'
echo '        Now you need to either manually add the library libxml2.tbd to the '
echo '        project under "General -> Linked Frameworks and Libraries" *or* '
echo '        run the ./update_project.rb script which will do it for you.'
echo '        Either of the above are needed to prevent build errors! '
echo ''
echo '  Also note:'
echo '        Modifications to files in iOS/ will be clobbered the next    '
echo '        time this script is run.  If you intend on modifying the     '
echo '        program in Xcode, be sure to copy out modifications from iOS/ '
echo '        manually or by running ./copy_back_changes.sh.'
echo ''
echo '  Caveats for App Store & Ad-Hoc distribution:'
echo '        "Release" builds submitted to the app store fail unless the '
echo '        following things are done in "Build Settings" in Xcode: '
echo '            - "Strip Debug Symbols During Copy" = NO '
echo '            - "Strip Linked Product" = NO '
echo '            - "Strip Style" = Debugging Symbols '
echo '            - "Enable Bitcode" = NO '
echo '            - "Valid Architectures" = arm64 '
echo '            - "Symbols Hidden by Default" = NO '
echo ''
