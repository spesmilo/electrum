### Electrum-GRS - lightweight multi-coin client
Electrum-GRS provides a basic SPV wallet for GRSpay. It is a BIP-0044-compliant wallet based on the original Electrum for Bitcoin. This Electrum-GRS client uses Electrum servers to retrieve necessary blockchain headaer & transaction data, so no "Electrum-GRS server" is necessary.

Because of the Simplified Payment Verification nature of the wallet, services requiring Masternode communications, such as DarkSend and InstantX are not available.

Homepage: https://GRSpay.io/electrum-GRS




1. ELECTRUM_GRS ON LINUX
----------------------

 - Installer package is provided at https://GRSpay.io/electrum-GRS
 - To download and use:
    ```
    cd ~
    wget https://GRSpay.io/electrum-GRS/releases/v2.4.1/Electrum-GRS-2.4.1-Linux_x86_64.tgz
    tar -xpzvf Electrum-GRS-2.4.1-Linux_x86_64.tgz
    cd Electrum-GRS-2.4.1
    ./electrum-GRS_x86_64.bin
    ```


Once successfully installed simply type
   ```
   electrum-GRS
   ```
   Your wallets will be located in /home/YOUR_LOGIN_NAME/.electrum-GRS/wallets

Installation on 32bit machines is best achieved via github master or TAGGED branches

2. HOW OFFICIAL PACKAGES ARE CREATED
------------------------------------

See contrib/electrum-GRS-release/README.md for complete details on mazaclub release process

