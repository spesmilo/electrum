### Electrum-GRS - lightweight groestlcoin client
Electrum-GRS provides a basic SPV wallet for Groestlcoin. It is a BIP-0044-compliant wallet based on the original Electrum for Bitcoin. This Electrum-GRS client uses Electrum-GRS servers to retrieve necessary blockchain headers & transaction data, so no "Electrum-GRS server" is necessary.

Homepage: http://www.groestlcoin.org

1. ELECTRUM_GRS ON LINUX
----------------------

 - Installer package is provided at http://www.groestlcoin
 - To download and use:
    ```
    cd ~
    wget https://github.com/GroestlCoin/electrum-grs/releases/download/v2.5.4/Electrum-GRS-2.5.4_Linux_x86_64-Installer.bin
    ./Electrum-GRS-2.5.4_Linux_x86_64-Installer.bin
    ```


Once successfully installed simply type
   ```
   Electrum-GRS
   ```
   Your wallets will be located in /home/YOUR_LOGIN_NAME/.Electrum-GRS/wallets

Installation on 32bit machines is best achieved via github master or TAGGED branches

2. HOW OFFICIAL PACKAGES ARE CREATED
------------------------------------

See contrib/electrum-GRS-release/README.md for complete details on mazaclub release process

