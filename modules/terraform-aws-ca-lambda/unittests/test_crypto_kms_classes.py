"""
Unit tests for crypto_kms_classes.py — regression tests for issue #606.

AWS KMS ``Sign`` rejects a RAW ``Message`` longer than 4096 bytes. The KMS-backed
key classes therefore hash the data locally and sign the fixed-size digest with
``MessageType="DIGEST"``. These tests assert that behaviour for both the RSA and
the Elliptic Curve key classes, across every ECDSA key size the module supports
(``ECC_NIST_P256``/``P384``/``P521``), including a payload larger than 4096 bytes.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID

from utils.certs.crypto_kms_classes import (
    AWSKMSEllipticCurvePrivateKey,
    AWSKMSMLDSA44PrivateKey,
    AWSKMSMLDSA65PrivateKey,
    AWSKMSMLDSA87PrivateKey,
    AWSKMSRSAPrivateKey,
)

# A payload comfortably larger than the 4096-byte KMS RAW limit (the regression case).
LARGE_PAYLOAD = b"a" * 5000

# hash_algorithm -> (KMS SigningAlgorithm, expected digest length in bytes, hash class)
ECDSA_VARIANTS = {
    "sha256": ("ECDSA_SHA_256", 32, hashes.SHA256),
    "sha384": ("ECDSA_SHA_384", 48, hashes.SHA384),
    "sha512": ("ECDSA_SHA_512", 64, hashes.SHA512),
}


@pytest.mark.parametrize("hash_algorithm,expected", list(ECDSA_VARIANTS.items()))
@patch("utils.certs.crypto_kms_classes.boto3")
def test_ec_sign_uses_digest_message_type(mock_boto3, hash_algorithm, expected):
    """EC sign hashes locally and signs the digest with MessageType=DIGEST for every curve."""
    signing_algorithm, digest_len, hash_class = expected

    mock_client = MagicMock()
    mock_client.sign.return_value = {"Signature": b"signature"}
    mock_boto3.client.return_value = mock_client

    private_key = AWSKMSEllipticCurvePrivateKey("test-key-id", hash_algorithm)

    # Use a real cryptography signature algorithm, as x509 signing does in production.
    signature = private_key.sign(LARGE_PAYLOAD, ec.ECDSA(hash_class()))

    assert signature == b"signature"
    mock_client.sign.assert_called_once()
    _, kwargs = mock_client.sign.call_args
    assert kwargs["MessageType"] == "DIGEST"
    assert kwargs["SigningAlgorithm"] == signing_algorithm
    assert kwargs["KeyId"] == "test-key-id"

    expected_digest = hashlib.new(hash_algorithm, LARGE_PAYLOAD).digest()
    assert kwargs["Message"] == expected_digest
    # The digest is fixed-size and well within the 4096-byte KMS limit.
    assert len(kwargs["Message"]) == digest_len
    assert len(kwargs["Message"]) <= 4096


@patch("utils.certs.crypto_kms_classes.boto3")
def test_rsa_sign_uses_digest_message_type(mock_boto3):
    """RSA sign hashes locally with sha256 and signs the digest with MessageType=DIGEST."""
    mock_client = MagicMock()
    mock_client.sign.return_value = {"Signature": b"signature"}
    mock_boto3.client.return_value = mock_client

    private_key = AWSKMSRSAPrivateKey("test-key-id")

    # Use real cryptography padding/hash objects, as x509 signing does in production.
    signature = private_key.sign(LARGE_PAYLOAD, padding.PKCS1v15(), hashes.SHA256())

    assert signature == b"signature"
    mock_client.sign.assert_called_once()
    _, kwargs = mock_client.sign.call_args
    assert kwargs["MessageType"] == "DIGEST"
    assert kwargs["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_256"
    assert kwargs["KeyId"] == "test-key-id"

    expected_digest = hashlib.sha256(LARGE_PAYLOAD).digest()
    assert kwargs["Message"] == expected_digest
    assert len(kwargs["Message"]) == 32
    assert len(kwargs["Message"]) <= 4096


@patch("utils.certs.crypto_kms_classes.boto3")
def test_ec_sign_rejects_unknown_hash_algorithm(mock_boto3):
    """An unsupported hash algorithm raises NotImplementedError before calling KMS."""
    mock_boto3.client.return_value = MagicMock()

    private_key = AWSKMSEllipticCurvePrivateKey("test-key-id", "md5")

    with pytest.raises(NotImplementedError):
        private_key.sign(LARGE_PAYLOAD, ec.ECDSA(hashes.SHA256()))


# KMS shim class -> local pyca key class and expected X.509 signature algorithm OID,
# covering all three AWS KMS ML-DSA key specs (ML_DSA_44 / ML_DSA_65 / ML_DSA_87)
ML_DSA_VARIANTS = {
    "ML_DSA_44": (AWSKMSMLDSA44PrivateKey, mldsa.MLDSA44PrivateKey, SignatureAlgorithmOID.ML_DSA_44),
    "ML_DSA_65": (AWSKMSMLDSA65PrivateKey, mldsa.MLDSA65PrivateKey, SignatureAlgorithmOID.ML_DSA_65),
    "ML_DSA_87": (AWSKMSMLDSA87PrivateKey, mldsa.MLDSA87PrivateKey, SignatureAlgorithmOID.ML_DSA_87),
}


def mock_ml_dsa_kms_client(local_key):
    """Mock KMS client backed by a locally generated ML-DSA key: GetPublicKey returns its
    DER SPKI as KMS does, and Sign performs external-mu signing as KMS ML_DSA_SHAKE_256
    with MessageType=EXTERNAL_MU does, so signatures can be genuinely verified"""
    mock_client = MagicMock()
    mock_client.get_public_key.return_value = {
        "PublicKey": local_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    }

    def kms_sign(**kwargs):
        assert kwargs["SigningAlgorithm"] == "ML_DSA_SHAKE_256"
        assert kwargs["MessageType"] == "EXTERNAL_MU"
        # mu is always the fixed-size 64-byte message representative (FIPS 204)
        assert len(kwargs["Message"]) == 64
        return {"Signature": local_key.sign_mu(kwargs["Message"])}

    mock_client.sign.side_effect = kms_sign
    return mock_client


@pytest.mark.parametrize("key_spec,variant", list(ML_DSA_VARIANTS.items()))
@patch("utils.certs.crypto_kms_classes.boto3")
def test_ml_dsa_sign_uses_external_mu(mock_boto3, key_spec, variant):  # pylint:disable=unused-argument
    """ML-DSA sign computes mu locally and signs via KMS EXTERNAL_MU for every key spec,
    producing a signature that verifies as pure ML-DSA over the original message
    (equivalent to what KMS RAW signing produces)."""
    shim_class, local_class, _ = variant
    local_key = local_class.generate()
    mock_boto3.client.return_value = mock_ml_dsa_kms_client(local_key)

    private_key = shim_class("test-key-id")

    signature = private_key.sign(LARGE_PAYLOAD)

    _, kwargs = mock_boto3.client.return_value.sign.call_args
    assert kwargs["KeyId"] == "test-key-id"

    # an external-mu signature is a valid ML-DSA signature over the original message:
    # pure ML-DSA verification over the (larger than 4096-byte) payload must succeed
    local_key.public_key().verify(signature, LARGE_PAYLOAD)


@pytest.mark.parametrize("key_spec,variant", list(ML_DSA_VARIANTS.items()))
@patch("utils.certs.crypto_kms_classes.boto3")
def test_ml_dsa_x509_certificate_signing(mock_boto3, key_spec, variant):
    """X.509 certificate signing via the KMS shim writes the correct RFC 9881 signature
    algorithm OID and produces a verifiable certificate for every ML-DSA key spec."""
    shim_class, local_class, expected_oid = variant
    local_key = local_class.generate()
    mock_boto3.client.return_value = mock_ml_dsa_kms_client(local_key)

    private_key = shim_class("test-key-id")
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{key_spec} test CA")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(private_key, None)
    )

    assert cert.signature_algorithm_oid == expected_oid
    # the certificate must verify with the genuine ML-DSA public key
    local_key.public_key().verify(cert.signature, cert.tbs_certificate_bytes)


@patch("utils.certs.crypto_kms_classes.boto3")
def test_ml_dsa_sign_rejects_context(mock_boto3):
    """ML-DSA context strings are not supported by KMS external-mu signing."""
    local_key = mldsa.MLDSA44PrivateKey.generate()
    mock_boto3.client.return_value = mock_ml_dsa_kms_client(local_key)

    private_key = AWSKMSMLDSA44PrivateKey("test-key-id")

    with pytest.raises(NotImplementedError):
        private_key.sign(b"data", b"context")
