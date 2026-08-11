"""
Local unit tests for certificate chain validation in utils.modules.certs.crypto.

These tests build CA hierarchies in memory with pyca/cryptography, so they run
without a deployed CA or AWS credentials, and prove the validation code accepts
RSA, ECDSA and ML-DSA (FIPS 204 post-quantum) certificate chains.
"""

import pytest
from assertpy import assert_that
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import utils.modules.certs.crypto as certs_crypto
from utils.modules.certs.crypto import (
    InvalidCertificateError,
    certificate_validated,
    convert_truststore,
    crypto_encode_private_key,
    crypto_tls_cert_signing_request,
    create_csr_info,
    generate_key,
)

try:
    mldsa.MLDSA44PrivateKey.generate()
    ML_DSA_SUPPORTED = True
except UnsupportedAlgorithm:
    ML_DSA_SUPPORTED = False

requires_ml_dsa = pytest.mark.skipif(not ML_DSA_SUPPORTED, reason="ML-DSA not supported by cryptography backend")

CRL_DP_URL = "http://crl.example.com/issuing-ca.crl"

PURPOSE_EKU_OIDS = {
    "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
    "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
}


def _generate_key(algorithm):
    if algorithm == "rsa":
        return generate_key("rsa", 2048)
    return generate_key(algorithm)


def _sign(builder, key):
    if isinstance(key, (mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey)):
        return builder.sign(key, None)
    return builder.sign(key, hashes.SHA256())


def _subject(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _make_ca_certificate(common_name, key, issuer_cert=None, issuer_key=None, path_length=None):
    """Self-signed root CA if no issuer is given, otherwise an issuing CA signed by the issuer"""
    issuer_name = issuer_cert.subject if issuer_cert is not None else _subject(common_name)
    signing_key = issuer_key if issuer_key is not None else key

    builder = (
        x509.CertificateBuilder()
        .subject_name(_subject(common_name))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
    )
    if issuer_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False
        )

    return _sign(builder, signing_key)


def _make_leaf_certificate(  # pylint:disable=too-many-arguments,too-many-positional-arguments
    common_name,
    key,
    issuer_cert,
    issuer_key,
    purposes=("client_auth", "server_auth"),
    key_encipherment=True,
    crl_dp_url=None,
    lifetime=timedelta(days=1),
):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_subject(common_name))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) - timedelta(minutes=5) + lifetime)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=key_encipherment,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([PURPOSE_EKU_OIDS[p] for p in purposes]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.example.com")]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False)
    )
    if crl_dp_url is not None:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl_dp_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )

    return _sign(builder, issuer_key)


def _make_crl(issuer_cert, issuer_key, revoked_serials=()):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(datetime.now(timezone.utc) - timedelta(minutes=5))
        .next_update(datetime.now(timezone.utc) + timedelta(days=1))
    )
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(datetime.now(timezone.utc) - timedelta(minutes=5))
            .build()
        )

    return _sign(builder, issuer_key)


def _make_chain(
    root_algorithm, issuing_algorithm=None, leaf_algorithm=None, purposes=("client_auth", "server_auth"), **leaf_kwargs
):
    """Build root CA, issuing CA and leaf certificate; return leaf bundle PEM, chain objects and keys"""
    issuing_algorithm = issuing_algorithm or root_algorithm
    leaf_algorithm = leaf_algorithm or issuing_algorithm

    root_key = _generate_key(root_algorithm)
    issuing_key = _generate_key(issuing_algorithm)
    leaf_key = _generate_key(leaf_algorithm)

    root_cert = _make_ca_certificate("Test Root CA", root_key, path_length=1)
    issuing_cert = _make_ca_certificate("Test Issuing CA", issuing_key, root_cert, root_key, path_length=0)
    leaf_cert = _make_leaf_certificate("test.example.com", leaf_key, issuing_cert, issuing_key, purposes, **leaf_kwargs)

    bundle_pem = b"".join(
        cert.public_bytes(serialization.Encoding.PEM) for cert in (leaf_cert, issuing_cert, root_cert)
    ).decode("utf-8")

    return bundle_pem, leaf_cert, issuing_cert, issuing_key


CHAIN_ALGORITHMS = [
    pytest.param("ecdsa", id="ecdsa"),
    pytest.param("rsa", id="rsa"),
    pytest.param("ml-dsa-44", id="ml-dsa-44", marks=requires_ml_dsa),
    pytest.param("ml-dsa-65", id="ml-dsa-65", marks=requires_ml_dsa),
    pytest.param("ml-dsa-87", id="ml-dsa-87", marks=requires_ml_dsa),
]


@pytest.mark.parametrize("algorithm", CHAIN_ALGORITHMS)
def test_certificate_validated(algorithm):
    bundle_pem, _, _, _ = _make_chain(algorithm)
    trust_roots = convert_truststore(bundle_pem)

    assert_that(certificate_validated(bundle_pem, trust_roots, check_crl=False)).is_true()


@requires_ml_dsa
def test_certificate_validated_mixed_ml_dsa_chain():
    """ML-DSA-65 root CA, ML-DSA-44 issuing CA and classical EC subject key, per the PQC plan scope"""
    bundle_pem, _, _, _ = _make_chain("ml-dsa-65", issuing_algorithm="ml-dsa-44", leaf_algorithm="ecdsa")
    trust_roots = convert_truststore(bundle_pem)

    assert_that(certificate_validated(bundle_pem, trust_roots, check_crl=False)).is_true()


@pytest.mark.parametrize("algorithm", CHAIN_ALGORITHMS)
def test_certificate_not_valid_for_purpose(algorithm):
    bundle_pem, _, _, _ = _make_chain(algorithm, purposes=("server_auth",))
    trust_roots = convert_truststore(bundle_pem)

    assert_that(certificate_validated).raises(InvalidCertificateError).when_called_with(
        bundle_pem, trust_roots, ["client_auth"], check_crl=False
    ).is_equal_to("The X.509 certificate provided is not valid for the purpose of client auth")


def test_certificate_untrusted_chain_rejected():
    bundle_pem, _, _, _ = _make_chain("ecdsa")
    other_bundle_pem, _, _, _ = _make_chain("ecdsa")
    unrelated_trust_roots = convert_truststore(other_bundle_pem)

    with pytest.raises(InvalidCertificateError, match="could not be validated"):
        certificate_validated(bundle_pem, unrelated_trust_roots, check_crl=False)


def test_expired_certificate_rejected():
    bundle_pem, _, _, _ = _make_chain("ecdsa", lifetime=timedelta(minutes=1))
    trust_roots = convert_truststore(bundle_pem)

    with pytest.raises(InvalidCertificateError, match="could not be validated"):
        certificate_validated(bundle_pem, trust_roots, check_crl=False)


@pytest.mark.parametrize("algorithm", CHAIN_ALGORITHMS)
def test_revoked_certificate_rejected(algorithm, monkeypatch):
    bundle_pem, leaf_cert, issuing_cert, issuing_key = _make_chain(algorithm, crl_dp_url=CRL_DP_URL)
    trust_roots = convert_truststore(bundle_pem)

    crl = _make_crl(issuing_cert, issuing_key, revoked_serials=[leaf_cert.serial_number])
    monkeypatch.setattr(certs_crypto, "_fetch_crl", lambda url: crl)

    with pytest.raises(InvalidCertificateError, match="revoked"):
        certificate_validated(bundle_pem, trust_roots)


@pytest.mark.parametrize("algorithm", CHAIN_ALGORITHMS)
def test_certificate_not_on_crl_validated(algorithm, monkeypatch):
    bundle_pem, _, issuing_cert, issuing_key = _make_chain(algorithm, crl_dp_url=CRL_DP_URL)
    trust_roots = convert_truststore(bundle_pem)

    crl = _make_crl(issuing_cert, issuing_key)
    monkeypatch.setattr(certs_crypto, "_fetch_crl", lambda url: crl)

    assert_that(certificate_validated(bundle_pem, trust_roots)).is_true()


def test_crl_with_invalid_signature_rejected(monkeypatch):
    bundle_pem, _, issuing_cert, _ = _make_chain("ecdsa", crl_dp_url=CRL_DP_URL)
    trust_roots = convert_truststore(bundle_pem)

    # CRL signed by a key that isn't the issuing CA's
    rogue_key = _generate_key("ecdsa")
    crl = _make_crl(issuing_cert, rogue_key)
    monkeypatch.setattr(certs_crypto, "_fetch_crl", lambda url: crl)

    with pytest.raises(InvalidCertificateError, match="CRL signature verification failed"):
        certificate_validated(bundle_pem, trust_roots)


def test_unreachable_crl_hard_fails(monkeypatch):
    bundle_pem, _, _, _ = _make_chain("ecdsa", crl_dp_url=CRL_DP_URL)
    trust_roots = convert_truststore(bundle_pem)

    def _unreachable(url):
        raise OSError("connection refused")

    monkeypatch.setattr(certs_crypto, "_fetch_crl", _unreachable)

    with pytest.raises(InvalidCertificateError, match="Unable to retrieve CRL"):
        certificate_validated(bundle_pem, trust_roots)


@requires_ml_dsa
@pytest.mark.parametrize("algorithm", ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"])
def test_ml_dsa_certificate_signing_request(algorithm):
    private_key = generate_key(algorithm)
    csr_info = create_csr_info("pqc-test.example.com")

    csr_pem = crypto_tls_cert_signing_request(private_key, csr_info)
    csr = x509.load_pem_x509_csr(csr_pem)

    assert_that(csr.is_signature_valid).is_true()
    assert_that(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value).is_equal_to("pqc-test.example.com")


@requires_ml_dsa
def test_ml_dsa_private_key_encoding_round_trip():
    private_key = generate_key("ml-dsa-65")

    key_pem = crypto_encode_private_key(private_key)
    reloaded = serialization.load_pem_private_key(key_pem, password=None)

    assert_that(reloaded).is_instance_of(mldsa.MLDSA65PrivateKey)
