# Python Jade Library

This is a slightly modified version of the official [Jade](https://github.com/Blockstream/Jade) python library.

This modified version was made from tag [0.1.32](https://github.com/Blockstream/Jade/releases/tag/0.1.32).

Intention is to fold these modifications back into Jade repo, for future api release.

## Changes

- Removed BLE module, reducing transitive dependencies
- Comment create_ble() functions
- More robust 'read_cbor_respose()' function - backported from jade master
- Tweak jade_serial.py to unset RTS line - backported from jade master
- _http_request() function removed, so cannot be used as unintentional fallback