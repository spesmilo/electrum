# -*- coding: utf-8 -*-
"""Satochip device certificate chain validation, using only the
'cryptography' library (an Electrum dependency).

Ported from pysatochip's certificate_validator (with the pyOpenSSL and
pycryptodomex backends dropped). The chain is: Satochip personalization root
CA (secp384r1) -> Satochip personalization subCA (secp256k1) -> device
certificate (secp256k1), exported from the card. A challenge-response against
the device key then proves the key is actually loaded in the card (see
CardConnector.card_challenge_response_pki).

The root and subCA certificates are the ones published in pysatochip's cert/
directory; they are embedded here so the plugin is self-contained (and works
when loaded from a zip). Test PKI certificates are kept so that test cards
are reported as such instead of as counterfeit.
"""

import logging
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_logger = logging.getLogger(__name__)

CA_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIICLTCCAbOgAwIBAgIBATAKBggqhkjOPQQDBDBeMQswCQYDVQQGEwJCRTERMA8G
A1UECAwIQnJ1c3NlbHMxEDAOBgNVBAoMB1RvcG9yaW4xKjAoBgNVBAMMIVRvcG9y
aW4gUGVyc29uYWxpemF0aW9uIFJvb3QgQ0EgMTAeFw0yMDEyMDExMjAwMDBaFw00
MDEyMDExMjAwMDBaMF4xCzAJBgNVBAYTAkJFMREwDwYDVQQIDAhCcnVzc2VsczEQ
MA4GA1UECgwHVG9wb3JpbjEqMCgGA1UEAwwhVG9wb3JpbiBQZXJzb25hbGl6YXRp
b24gUm9vdCBDQSAxMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE5ZPgeQ54Y5NdTJM4
uYU0f+vDK/D5XI9pY69i+EkgK4l++zKjsGMYY7gkEFzcqB1nQRn8ozss/0vYaMpk
oePYNqVd0ZQxwFcb/NLDyZQq3NzfTAmQjw6KMSvPL57R24K1o0UwQzASBgNVHRMB
Af8ECDAGAQH/AgEBMB0GA1UdDgQWBBRda9Hdoqr5lHwykRLBgkIVnUT6ITAOBgNV
HQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwQDaAAwZQIxAJTGtuRR9ceNqAXu5sAOp6yJ
RLdnio7RVMmIZWLishPolJFN9vPt7FSBDgxRnqUJVwIwXJNx20XtJJl6NwKLfMIK
nf1pE1NCQErS3wK9lLPZkr7uK/TpulrKJ+hc+1w7+UeU
-----END CERTIFICATE-----"""

SUBCA_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIICIDCCAaWgAwIBAgIBAzAKBggqhkjOPQQDBDBeMQswCQYDVQQGEwJCRTERMA8G
A1UECAwIQnJ1c3NlbHMxEDAOBgNVBAoMB1RvcG9yaW4xKjAoBgNVBAMMIVRvcG9y
aW4gUGVyc29uYWxpemF0aW9uIFJvb3QgQ0EgMTAeFw0yMDEyMDExMjAwMDBaFw00
MDEyMDExMjAwMDBaMHAxCzAJBgNVBAYTAkJFMREwDwYDVQQIDAhCcnVzc2VsczEQ
MA4GA1UECgwHVG9wb3JpbjERMA8GA1UECwwIU2F0b2NoaXAxKTAnBgNVBAMMIFNh
dG9jaGlwIFBlcnNvbmFsaXphdGlvbiBTdWJDQSAxMFYwEAYHKoZIzj0CAQYFK4EE
AAoDQgAEcTVxDGkXKyV0kaRXu+9gTrg654Xam6ktgDA/n+28+egjMmZDWroaha/6
+MPP/XBGeFAecmO0hppkgnUcwjRcw6NFMEMwEgYDVR0TAQH/BAgwBgEB/wIBADAd
BgNVHQ4EFgQUx9Plfp8o9ZCoticLc5x7CnSBriUwDgYDVR0PAQH/BAQDAgEGMAoG
CCqGSM49BAMEA2kAMGYCMQCmoDTdSMMSMogCm4l130drFFxC0wmbZwWE+xGjZIKL
9tXosnIzUx5VUqbeNXbvJBUCMQDVVRt4c4veIxdwWOv2DhJ9Ri/3it8R0v/eQ/jU
ppK2S2/ObbWSt5aAGi4EfpGZ93E=
-----END CERTIFICATE-----"""

# for testing purpose only (cards personalized with the test PKI)
TEST_CA_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIB/TCCAYOgAwIBAgIBATAKBggqhkjOPQQDBDBGMQswCQYDVQQGEwJCRTERMA8G
A1UECAwIQnJ1c3NlbHMxEDAOBgNVBAoMB1RvcG9yaW4xEjAQBgNVBAMMCVRFU1Qg
Q0EgMTAeFw0yMDEyMDExMjAwMDBaFw00MDEyMDExMjAwMDBaMEYxCzAJBgNVBAYT
AkJFMREwDwYDVQQIDAhCcnVzc2VsczEQMA4GA1UECgwHVG9wb3JpbjESMBAGA1UE
AwwJVEVTVCBDQSAxMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE/25Heq7rJvqxCcO4
wq+y9bAA5YC3dJhDpH8AIBHbJ+w4g4neVmQLyrW0wO1xH/R4Ne8Bb7GTA+YYy0/x
jtls6KHCgUFKBgCKtQK07CtSNWX6GViN8ZYDlvtBtZlWOi9Lo0UwQzASBgNVHRMB
Af8ECDAGAQH/AgEBMB0GA1UdDgQWBBRSKn/TwpJFN3wDFDpdi59W/zkThzAOBgNV
HQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwQDaAAwZQIwTxLhCePwLKVm13ZdmJcRf5YI
ePKRe+tk7Jew2oX7ZpoTVDbof4Glzv7aI31Csoa3AjEAg+EHbj8MgzJAcYvdbF8d
dH8pu5JVYRp2iZPnB36gvjCdiRc8xfTbTYauH8DrWeCr
-----END CERTIFICATE-----"""

TEST_SUBCA_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIICBzCCAY2gAwIBAgIBBzAKBggqhkjOPQQDBDBGMQswCQYDVQQGEwJCRTERMA8G
A1UECAwIQnJ1c3NlbHMxEDAOBgNVBAoMB1RvcG9yaW4xEjAQBgNVBAMMCVRFU1Qg
Q0EgMTAeFw0yMDEyMDExMjAwMDBaFw00MDEyMDExMjAwMDBaMHAxCzAJBgNVBAYT
AkJFMREwDwYDVQQIDAhCcnVzc2VsczEQMA4GA1UECgwHVG9wb3JpbjERMA8GA1UE
CwwIU2F0b2NoaXAxKTAnBgNVBAMMIFNhdG9jaGlwIFBlcnNvbmFsaXphdGlvbiBT
dWJDQSAxMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEgvUALg9mBMwQ5mxPMZY+9ltN
+/Fb0wSHmTyBtZf/6lfUv4P0jV9G4l402HOLopZa92KYGReggh8GPjnK1itPTaNF
MEMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUQIym/hHeoi7IQeNqZKay
TiZwgiUwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMEA2gAMGUCMQCuYiVJfOnV
NnWhnP1zdEq9J+/2QvPa5U4xhPiOKxY3F/AvGdYHnuJoVyYIBAd5B4wCMGhQ8Cyo
ZQfFcG9vih3KSrn0rgXqpY+k+ceOHoYc9/DsNyG8ycHZWZQ5dOWVfVPLCA==
-----END CERTIFICATE-----"""


def _not_valid_after(cert) -> datetime:
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _not_valid_before(cert) -> datetime:
    try:
        return cert.not_valid_before_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_before.replace(tzinfo=timezone.utc)


def _cert_to_text(cert) -> str:
    """Render a certificate as text for display (approximates openssl x509 -text)."""
    pubkey = cert.public_key()
    pubkey_bytes = pubkey.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    pubkey_hex = ':'.join(f'{b:02x}' for b in pubkey_bytes)
    sig_algo = f"ecdsa-with-{cert.signature_hash_algorithm.name.upper()}"
    lines = [
        "Certificate:",
        "    Data:",
        f"        Version: {cert.version.value + 1} ({cert.version.name.lower()})",
        f"        Serial Number: {cert.serial_number} ({hex(cert.serial_number)})",
        f"        Signature Algorithm: {sig_algo}",
        f"        Issuer: {cert.issuer.rfc4514_string()}",
        "        Validity",
        f"            Not Before: {_not_valid_before(cert)}",
        f"            Not After : {_not_valid_after(cert)}",
        f"        Subject: {cert.subject.rfc4514_string()}",
        "        Subject Public Key Info:",
        "            Public Key Algorithm: id-ecPublicKey",
        f"                Public-Key: ({pubkey.curve.key_size} bit)",
        f"                pub: {pubkey_hex}",
        f"                ASN1 OID: {pubkey.curve.name}",
        f"    Signature Algorithm: {sig_algo}",
        f"    Signature Value: {cert.signature.hex()}",
    ]
    return '\n'.join(lines)


class CertificateValidator:
    """Validate Satochip device certificate chains using the cryptography library."""

    def validate_certificate_chain(self, device_pem, device_type):
        _logger.debug("In validate_certificate_chain")

        result = self._validate_chain(device_pem, device_type, use_test=False)
        (is_valid, device_pubkey, txt_ca, txt_subca, txt_device, txt_error) = result
        if is_valid:
            return result

        # check with test ca
        _logger.warning("Certificate chain NOT VALID for production PKI")
        (is_valid_test, device_pubkey_test, txt_ca_test, txt_subca_test,
         txt_device_test, txt_error_test) = self._validate_chain(device_pem, device_type, use_test=True)
        if is_valid_test:
            is_valid_test = False
            txt_error_test = "WARNING: Chain certificate validated with TEST CA! NOT FOR PRODUCTION!"
            return (is_valid_test, device_pubkey_test, txt_ca_test,
                    txt_subca_test, txt_device_test, txt_error_test)
        return result

    def _validate_chain(self, device_pem, device_type, use_test=False):
        txt_ca = txt_subca = txt_device = txt_error = ""
        device_pubkey = bytes(65 * [0])

        if device_type != "Satochip":
            txt_error = "Unsupported card_type: " + str(device_type)
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        ca_pem = TEST_CA_CERT_PEM if use_test else CA_CERT_PEM
        subca_pem = TEST_SUBCA_CERT_PEM if use_test else SUBCA_CERT_PEM

        # parse certificates
        try:
            cert_ca = x509.load_pem_x509_certificate(ca_pem.encode('ascii'))
            txt_ca = _cert_to_text(cert_ca)
            cert_subca = x509.load_pem_x509_certificate(subca_pem.encode('ascii'))
            txt_subca = _cert_to_text(cert_subca)
            cert_device = x509.load_pem_x509_certificate(device_pem.encode('ascii'))
            txt_device = _cert_to_text(cert_device)
        except Exception as ex:
            txt_error = "Exception during pem certificates parsing: " + str(ex)
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        # check the chain links: subca signed by ca, device signed by subca
        txt_error = self._verify_link(cert_ca, cert_subca)
        if txt_error:
            txt_error = "Exception during subca validation: " + txt_error
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
        txt_error = self._verify_link(cert_subca, cert_device)
        if txt_error:
            txt_error = "Exception during device certificate validation: " + txt_error
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        # extract pubkey from device certificate (uncompressed, 65 bytes)
        device_pubkey = cert_device.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)

        return True, device_pubkey, txt_ca, txt_subca, txt_device, ""

    def _verify_link(self, issuer_cert, subject_cert) -> str:
        """Verify that subject_cert was issued and signed by issuer_cert, and
        that it is currently valid. Returns an error message, '' on success."""
        if subject_cert.issuer != issuer_cert.subject:
            return (f"issuer {subject_cert.issuer.rfc4514_string()} does not match "
                    f"CA subject {issuer_cert.subject.rfc4514_string()}")
        now = datetime.now(timezone.utc)
        if now < _not_valid_before(subject_cert):
            return f"certificate is not valid before {_not_valid_before(subject_cert)}"
        if now > _not_valid_after(subject_cert):
            return f"certificate expired on {_not_valid_after(subject_cert)}"
        try:
            issuer_cert.public_key().verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                ec.ECDSA(subject_cert.signature_hash_algorithm))
        except InvalidSignature:
            return "bad certificate signature"
        except Exception as ex:
            return str(ex)
        return ""
