### Electrum-GRS - lightweight groestlcoin client

Electrum-GRS provides a basic SPV wallet for Groestlcoin. It is a BIP-0044-compliant wallet based on the original Electrum for Bitcoin. This Electrum-GRS client uses Electrum-GRS servers to retrieve necessary blockchain headaer & transaction data, so no "Electrum-GRS server" is necessary.

Homepage: http://www.groestlcoin.org

1. Download the .pkg from http://www.groestlcoin.org
2. Double click Electrum-GRS.pkg
4. Follow instructions to install Electrum-GRS

Electrum-GRS will be installed by default to /Applications

Your wallets will be stored in /users/YOUR_LOGIN_NAME/.electrum-GRS/wallets

2. HOW OFFICIAL PACKAGES ARE CREATED
------------------------------------

contrib/mazaclub-release

 
The 'build' script will perform all the necessary tasks to 
create a release from release-tagged github sources

If all runs correctly, you''ll find a release set in the 
contrib/electrum-GRS-release/releases directory, complete with 
md5/sha1 sums, and gpg signatures for all files. 

Additional documentation is provided in the README in that dir.
Official Releases are created with a single OSX machine, boot2docker vm and docker

