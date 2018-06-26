#!/bin/bash

if [ ! -d iOS ]; then
    echo "Error: No iOS directory"
    exit 1
fi

projdir="iOS/app"
projdir_top="iOS/"

pushd . > /dev/null
cd $projdir

a=`find ElectronCash/ -type f -depth 1 -name \*.py -print`
b=`find ElectronCash/electroncash_gui -type f -name \*.py -print`
c=`find ElectronCash/electroncash -type f -name \*.py -print`
popd > /dev/null

pushd . > /dev/null
cd $projdir_top
res=`find Resources -type f -print`
ccode=`find CustomCode -type f -print`
popd > /dev/null

allYes=0
ct=0
skipped=0

function doIt() {
    f1=$1
    f2=$2
    dstInfo=$3

    if [ -e "$f1" ] && diff -q $f1 $f2 > /dev/null 2>&1; then
        true
    else
        while true; do
            answer=""
            prompt="$f1 changed -- copy back to $dstInfo ? ([y]es/[n]/[a]ll/[d]iff)"
            if [ "$allYes" != "1" ]; then
                echo ""
                echo "$prompt"
            fi
            if [ "$allYes" == "0" ]; then
                read answer
            fi
            if [ "$answer" == "d" ]; then
                diff -u $f1 $f2 | less
                echo ""
                continue
            fi
            break
        done
        if [ "$answer" == "a" ]; then
            allYes=1
        fi
        if [ "$answer" == "y" -o "$allYes" == "1" ]; then
            cp -v $f2 $f1
            let ct++
        else
            let skipped++
        fi
    fi
}

for file in $a $b; do
    f1="${file}"
    f2="${projdir}/${file}"
    doIt "$f1" "$f2" "ElectronCash/"
done

for f in $c; do
    file=`echo $f | cut -f 3- -d '/'`
    f1="../lib/${file}"
    f2="${projdir}/${f}"
    doIt "$f1" "$f2" "../lib/"
done

for file in $res; do
    f1="${file}"
    f2="${projdir_top}/${file}"
    doIt "$f1" "$f2" "Resources/"
done

for file in $ccode; do
    f1="${file}"
    f2="${projdir_top}/${file}"
    doIt "$f1" "$f2" "CustomCode/"
done

echo ""

if ((ct>0)); then
    echo "Copied back $ct changed file(s)"
fi

if ((skipped>0)); then
    echo "Skipped $skipped"
fi

if [ $skipped == 0 -a $ct == 0 ]; then
    echo "No changes detected in iOS/"
fi

echo "Done."

