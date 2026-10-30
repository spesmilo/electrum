This is a copy of the 3rd-party `foundation-ur-py` package,
a Python implementation of Blockchain Commons' Uniform Resources (UR),
ported from https://github.com/BlockchainCommons/bc-ur

It is used to encode and decode (animated) BC-UR QR codes.

At revision https://github.com/Foundation-Devices/foundation-ur-py/tree/a371f6355fb3433cc989ad5bf28f87a347b222fe/ur
(upstream is no longer maintained)

Modifications:
- excluded files not needed by us (tests, cbor_lite.py, crc32.py)
- use Electrum's `cbor` module for CBOR, and `zlib.crc32`
- fountain_encoder.Part: validated on construction (strict types, uint32 checksum, bounds and
  consistency checks for untrusted input: seq_len, message_len, fragment length)
- FountainDecoder: Gauss-Jordan elimination over GF(2) instead of the reference implementation's
  "peeling" decoder, so that it decodes as soon as the received parts determine the message.
  It reports progress as independent_part_count() instead of received_part_indexes,
  estimated_percent_complete() is exact, and the helpers only used for peeling are removed.
- FountainEncoder.next_part: seq_num wraps at 2**32, as in the reference implementation (was % MAX_UINT32)
- FountainEncoder: support `bytes` messages
- `Part` classes are frozen dataclasses, the decoder's `Part` is no longer nested in `FountainDecoder`,
  the encoder's `Part.cbor()` is renamed to `to_cbor()`
- RandomSampler: use naive float summation, as required by the spec
- utils.is_ur_type: check the whole type string
- no bare except (URDecoder.parse_sequence_component)
- relative imports, removed debug and dead code
- type annotations. For them, `Bytewords.decode` and `utils.join_bytes` return `bytes` instead of `bytearray`,
  the decoders' `is_success`/`is_failure` return `bool`, and `result_message`/`result_error` assert the result type
- PEP 8 formatting, ASCII headers and license
