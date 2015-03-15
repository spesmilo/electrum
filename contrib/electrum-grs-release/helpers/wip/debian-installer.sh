#!/bin/bash
###################
### work in progress
### 
PREFIX="/"


echo ""
echo "Self Extracting Tar File"
echo ""
echo "Example by Stuart Wells"
echo ""
echo "Extracting file into `pwd`"
SKIP=`awk '/^__TARFILE_FOLLOWS__/ { print NR + 1; exit 0; }' $0`

#remember our file name
THIS=`pwd`/$0

# take the tarfile and pipe it into tar
tail -n +$SKIP $THIS | tar -xz

#
# place any bash script here you need.
# Any script here will happen after the tar file extract.
cd Encompass-${VERSION}
###
# needs to properly install C extensions
##
echo "Installing Encompass-0.4.4"
dpkg -i python-encompass_0.4.4-1_all.deb
apt-get install -f

echo "Finished"
exit 0


# NOTE: Don't place any newline characters after the last line below.
__TARFILE_FOLLOWS__
