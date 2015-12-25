### Electrum-GRS - lightweight multi-coin client

Electrum-GRS provides a basic SPV wallet for GRSpay. It is a BIP-0044-compliant wallet based on the original Electrum for Bitcoin. This Electrum-GRS client uses Electrum servers to retrieve necessary blockchain headaer & transaction data, so no "Electrum-GRS server" is necessary.

Because of the Simplified Payment Verification nature of the wallet, services requiring Masternode communications, such as DarkSend and InstantX are not available.

Homepage: https://GRSpay.io/electrum-GRS

1. Download the .dmg from https://GRSpay.io/electrum-GRS
2. Open .dmg in Finder
3. Double Click Electrum-GRS.pkg
4. Follow instructions to install Electrum-GRS

Electrum-GRS will be installed by default to /Applications

Your Wallets will be stored in /Users/YOUR_LOGIN_NAME/.electrum-GRS/wallets

### KNOWN ISSUES



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

