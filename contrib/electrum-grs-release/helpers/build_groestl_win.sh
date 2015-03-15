 git clone https://github.com/groestlcoin/groestlcoin-hash-python
 cp sph_types.patch groestlcoin-hash-python
 cd groestlcoin-hash-python
 patch < sph_types.patch
 cd ..
 docker run -t -i \
    -e WINEPREFIX="/wine/wine-py2.7.8-32" \
    -v $(pwd)/groestlcoin-hash-python:/code \
    -v $(pwd)/helpers:/helpers \
    ogrisel/python-winbuilder wineconsole --backend=curses cmd 
   cp groestlcoin-hash-python/build/lib.win32-2.7/groestlcoin_hash.pyd helpers/groestlcoin_hash.pyd
                                                                             
