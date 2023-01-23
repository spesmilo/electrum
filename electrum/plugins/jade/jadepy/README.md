# Python Jade Library

This is a slightly modified version of the official [Jade](https://github.com/Blockstream/Jade) python library.

This modified version was made from tag [0.1.37](https://github.com/Blockstream/Jade/releases/tag/0.1.37).

Intention is to fold these modifications back into Jade repo, for future api release.

## Changes
- Removed BLE module, reducing transitive dependencies
- _http_request() function removed, so cannot be used as unintentional fallback
