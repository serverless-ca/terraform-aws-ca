"""
Unit tests for KMS key-spec driven crypto selection.

Selection is keyed on the KMS key spec from kms:DescribeKey rather than the KMS signing
algorithm string, because all three ML-DSA key specs share the single signing algorithm
ML_DSA_SHAKE_256, which cannot identify the parameter set (and so the certificate OID).
"""

from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.x509.oid import SignatureAlgorithmOID

from utils.certs.crypto import (
    crypto_hash_algorithm,
    crypto_hash_class,
    crypto_select_class,
    crypto_tls_ca_cert_signing_request,
)
from utils.certs.crypto_kms_classes import (
    AWSKMSEllipticCurvePrivateKey,
    AWSKMSMLDSA44PrivateKey,
    AWSKMSMLDSA65PrivateKey,
    AWSKMSMLDSA87PrivateKey,
    AWSKMSRSAPrivateKey,
)
from lambda_code.tls_cert.tls_cert import select_csr_crypto

EXPECTED_SELECTION = {
    "RSA_2048": (AWSKMSRSAPrivateKey, "sha256", hashes.SHA256),
    "RSA_3072": (AWSKMSRSAPrivateKey, "sha256", hashes.SHA256),
    "RSA_4096": (AWSKMSRSAPrivateKey, "sha256", hashes.SHA256),
    "ECC_NIST_P256": (AWSKMSEllipticCurvePrivateKey, "sha256", hashes.SHA256),
    "ECC_NIST_P384": (AWSKMSEllipticCurvePrivateKey, "sha384", hashes.SHA384),
    "ECC_NIST_P521": (AWSKMSEllipticCurvePrivateKey, "sha512", hashes.SHA512),
    "ML_DSA_44": (AWSKMSMLDSA44PrivateKey, None, None),
    "ML_DSA_65": (AWSKMSMLDSA65PrivateKey, None, None),
    "ML_DSA_87": (AWSKMSMLDSA87PrivateKey, None, None),
}


@pytest.mark.parametrize("key_spec,expected", list(EXPECTED_SELECTION.items()))
def test_crypto_selection_by_key_spec(key_spec, expected):
    """Every supported KMS key spec selects the right key class and hash, ML-DSA has no hash."""
    expected_class, expected_hash_name, expected_hash_class = expected

    assert crypto_select_class(key_spec) is expected_class
    assert crypto_hash_algorithm(key_spec) == expected_hash_name
    if expected_hash_class is None:
        assert crypto_hash_class(key_spec) is None
    else:
        assert isinstance(crypto_hash_class(key_spec), expected_hash_class)


@pytest.mark.parametrize("function", [crypto_select_class, crypto_hash_algorithm, crypto_hash_class])
def test_unsupported_key_spec_rejected(function):
    with pytest.raises(ValueError):
        function("ECC_SECG_P256K1")


@pytest.mark.parametrize(
    "issuing_ca_key_spec,expected",
    [
        ("ECC_NIST_P256", ("ECC_NIST_P256", "ECDSA_SHA_256")),
        ("ECC_NIST_P384", ("ECC_NIST_P256", "ECDSA_SHA_256")),
        ("RSA_2048", ("RSA_2048", "RSASSA_PKCS1_V1_5_SHA_256")),
        # KMS GenerateDataKeyPair doesn't support ML-DSA, so the no-CSR flow issues
        # classical (EC) subject keys under a post-quantum chain
        ("ML_DSA_44", ("ECC_NIST_P256", "ECDSA_SHA_256")),
        ("ML_DSA_65", ("ECC_NIST_P256", "ECDSA_SHA_256")),
        ("ML_DSA_87", ("ECC_NIST_P256", "ECDSA_SHA_256")),
    ],
)
@patch("lambda_code.tls_cert.tls_cert.kms_describe_key")
@patch("lambda_code.tls_cert.tls_cert.kms_get_kms_key_id")
def test_select_csr_crypto(mock_get_key_id, mock_describe_key, issuing_ca_key_spec, expected):
    mock_get_key_id.return_value = "test-key-id"
    mock_describe_key.return_value = {"KeySpec": issuing_ca_key_spec}

    assert select_csr_crypto("test-issuing-ca") == expected


def test_ml_dsa_ca_csr_signed_without_hash_algorithm():
    """CA CSR generation signs with algorithm=None for a local ML-DSA key, and the
    resulting CSR carries the RFC 9881 ML-DSA signature algorithm OID."""
    private_key = mldsa.MLDSA44PrivateKey.generate()

    csr_pem = crypto_tls_ca_cert_signing_request(private_key, "pqc-issuing-ca")
    csr = x509.load_pem_x509_csr(csr_pem)

    assert csr.signature_algorithm_oid == SignatureAlgorithmOID.ML_DSA_44
    assert csr.is_signature_valid
