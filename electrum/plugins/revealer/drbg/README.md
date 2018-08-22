This Python library provides a cryptographically secure pseudorandom number generator.
Specifically, it implements **HMAC_DRBG** (SHA-512) as specified in
[NIST SP 800-90A](http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf).

For simplicity, this library currently does not track the seed period,
so the `generate` function always returns the requested number of bytes.
It is the user's responsibility to periodically reseed the PRNG.

This library is tested with NIST-provided test vectors.
To run the tests:

    $ python hmac_drbg_tests.py 
    Passed all 224 tests.

**See also**: [go-crypto](https://github.com/davidlazar/go-crypto).
