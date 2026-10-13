This is a copy of the 3rd-party `foundation-ur-py` package,
a Python implementation of Blockchain Commons' Uniform Resources (UR),
ported from https://github.com/BlockchainCommons/bc-ur

It is used to encode and decode (animated) BC-UR QR codes.

At revision https://github.com/Foundation-Devices/foundation-ur-py/tree/a371f6355fb3433cc989ad5bf28f87a347b222fe/ur
(upstream is no longer maintained)

Modifications:
- type annotations. For them, `Bytewords.decode` and `utils.join_bytes` return `bytes` instead of `bytearray`,
  the decoders' `is_success`/`is_failure` return `bool`, and `result_message`/`result_error` assert the result type
- PEP 8 formatting, ASCII headers and license
