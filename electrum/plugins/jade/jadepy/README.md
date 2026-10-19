# Python Jade Library

This is a slightly modified version of the official [Jade](https://github.com/Blockstream/Jade) python library.

This modified version was made from tag [1.0.31](https://github.com/Blockstream/Jade/releases/tag/1.0.31).

## Changes

- Removed BLE module, reducing transitive dependencies
- _http_request() function removed, so cannot be used as unintentional fallback
- Backported support for cbor2 6.x from upstream commits 9857bed93a and 91cc2edb02,
  but wrapping cbor2's CBORDecodeEOF in EOFError instead of exposing it as self.EOFError
