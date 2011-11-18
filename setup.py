#!/usr/bin/python

#python mysetup.py sdist --format=zip,gztar


from distutils.core import setup

version = "0.26b"

setup(name = "Electrum",
    version = version,
    description = "Lightweight Bitcoin Wallet",
    author = "thomasv",
    license = "GNU GPLv3",
    url = "http://ecdsa/electrum",
    long_description = """Lightweight Bitcoin Wallet""" 
) 

if __name__ == '__main__':
    import sys, re, shutil
    if sys.argv[1]=='sdist':
        _tgz="Electrum-%s.tar.gz"%version
        _zip="Electrum-%s.zip"%version
        shutil.copyfile("dist/"+_tgz ,'/var/www/electrum/'+_tgz)
        shutil.copyfile("dist/"+_zip,'/var/www/electrum/'+_zip)
        f = open("/var/www/electrum/index.html")
        s = f.read()
        f.close()
        s = re.sub("Electrum-([\d\.]*?)\.tar\.gz", _tgz, s)
        s = re.sub("Electrum-([\d\.]*?)\.zip", _zip, s)
        f = open("/var/www/electrum/index.html","w")
        f.write(s)
        f.close()
        
