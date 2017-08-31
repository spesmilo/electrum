#!/usr/bin/bash


whereis pip3
if [ $? -ne 0 ] ; then echo "Install pip3" ; exit ; fi

#Install pure python modules in electrum directory
cd ../..
pip3 install pyaes -t ./packages
pip3 install ecdsa -t ./packages
pip3 install pbkdf2 -t ./packages
pip3 install requests -t ./packages
pip3 install qrcode -t ./packages
pip3 install protobuf -t ./packages
pip3 install dnspython -t ./packages
pip3 install jsonrpclib-pelix -t ./packages
pip3 install PySocks -t ./packages

