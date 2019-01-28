#!/bin/bash

. ./common.sh

dir1="iOS/app/${compact_name}"
dir2="iOS/app_packages"

if [ ! -d "$dir1" -o ! -d "$dir2" ]; then
	echo "Cannot find the iOS/app/${compact_name} python sources. Did you forget to run ./make_ios_project.sh"'?'
	exit 1
fi


if [ "$1" == "-k" ]; then
	find "$dir1" "$dir2" -type d -name __pycache__ -exec rm -fvr {} \; 
	find "$dir1" "$dir2" -type f -name \*.pyc -exec rm -fvr {} \;
elif [ -n "$1" ]; then
	echo "Usage: $0 [-k]"
	echo "    -k   Klean.  That is, remove all __pycache__ dirs that were created by this script."
	echo ""
	echo "Running without options recompiles everything in $dir1 and $dir2"
	echo ""
else
	originaldir=`pwd`
	cd "$dir1" 
	python3.5 -O -m compileall . || exit 1
	cd "$originaldir" 
	cd "$dir2"
	python3.5 -O -m compileall . || exit 1
	cd "$originaldir"
fi



