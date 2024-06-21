import os
import json

from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import (
    AccessDescription,
    UniformResourceIdentifier,
    PolicyInformation,
    ObjectIdentifier,
)
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization
from validators import domain as domain_validator
from utils.certs.crypto import (
    crypto_select_class,
    crypto_hash_algorithm,
    crypto_hash_class,
)


domain = os.environ.get("DOMAIN")
env_name = os.environ["ENVIRONMENT_NAME"]
issuing_ca_info = json.loads(os.environ["ISSUING_CA_INFO"])
max_cert_lifetime = int(os.environ["MAX_CERT_LIFETIME"])
project = os.environ["PROJECT"]
public_crl = os.environ["PUBLIC_CRL"]
root_ca_info = json.loads(os.environ["ROOT_CA_INFO"])


def ca_name(hierarchy):
    if env_name in ["prd", "prod"]:
        return f"{project}-{hierarchy.lower()}-ca"

    return f"{project}-{hierarchy.lower()}-ca-{env_name}"


def ca_construct_subject_name(ca_info, ca_hierarchy_type="root"):
    """Constructs subject name for CA certificate"""
    country = ca_info.get("country")
    state = ca_info.get("state")
    locality = ca_info.get("locality")
    organization = ca_info.get("organization")
    organizational_unit = ca_info.get("organizationalUnit")
    common_name = ca_info.get("commonName") or f"Serverless {ca_hierarchy_type.title()} CA"
    email_address = ca_info.get("emailAddress")

    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]

    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))

    if email_address:
        attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))

    if locality:
        attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

    if organizational_unit:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))

    if state:
        attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))

    return x509.Name(attributes)


def get_subject_attribute_or_none(csr_cert, attribute):
    if csr_cert.subject.get_attributes_for_oid(attribute):
        return csr_cert.subject.get_attributes_for_oid(attribute)[0].value
    return None


def tls_cert_construct_subject_name(csr_cert, cert_request_info):
    """Constructs subject name for end entity certificate"""
    # subject values from CSR
    common_name = csr_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    country = get_subject_attribute_or_none(csr_cert, NameOID.COUNTRY_NAME)
    email_address = get_subject_attribute_or_none(csr_cert, NameOID.EMAIL_ADDRESS)
    locality = get_subject_attribute_or_none(csr_cert, NameOID.LOCALITY_NAME)
    state = get_subject_attribute_or_none(csr_cert, NameOID.STATE_OR_PROVINCE_NAME)
    organization = get_subject_attribute_or_none(csr_cert, NameOID.ORGANIZATION_NAME)
    organizational_unit = get_subject_attribute_or_none(csr_cert, NameOID.ORGANIZATIONAL_UNIT_NAME)

    # overwrite subject values from CSR with cert_request_info values if present
    common_name = cert_request_info.get("CommonName") or common_name
    country = cert_request_info.get("Country") or country
    email_address = cert_request_info.get("EmailAddress") or email_address
    state = cert_request_info.get("State") or state
    locality = cert_request_info.get("Locality") or locality
    organization = cert_request_info.get("Organization") or organization
    organizational_unit = cert_request_info.get("OrganizationalUnit") or organizational_unit

    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]

    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))

    if email_address:
        attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))

    if locality:
        attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

    if organizational_unit:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))

    if state:
        attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))

    return x509.Name(attributes)


def ca_kms_sign_ca_certificate_request(
    csr_cert, ca_cert, kms_key_id, kms_signing_algorithm="RSASSA_PKCS1_V1_5_SHA_256"
):
    """Sign CA certificate signing request using private key in AWS KMS"""

    # get Issuing CA info
    path_length_constraint = issuing_ca_info.get("pathLengthConstraint")
    lifetime = issuing_ca_info.get("lifetime") or 3650
    subject = ca_construct_subject_name(issuing_ca_info, "issuing")

    crl_dp = x509.DistributionPoint(
        [UniformResourceIdentifier(f"http://{domain}/{ca_name('root')}.crl")],
        relative_name=None,
        reasons=None,
        crl_issuer=None,
    )

    aia = x509.AuthorityInformationAccess(
        [
            AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                UniformResourceIdentifier(f"http://{domain}/{ca_name('root')}.crt"),
            )
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr_cert.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=lifetime))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr_cert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
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
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=path_length_constraint,
            ),
            critical=True,
        )
    )

    if public_crl == "enabled":
        cert = cert.add_extension(x509.CRLDistributionPoints([crl_dp]), critical=False)
        cert = cert.add_extension(aia, critical=False)

    cert = cert.sign(
        crypto_select_class(kms_signing_algorithm)(kms_key_id, crypto_hash_algorithm(kms_signing_algorithm)),
        crypto_hash_class(kms_signing_algorithm),
    )

    print(f"certificate serial number {cert.serial_number} issued for {cert.subject}")

    return cert.public_bytes(serialization.Encoding.PEM)


def ca_build_cert(csr_cert, ca_cert, lifetime, delta, cert_request_info):
    purposes = cert_request_info["Purposes"]

    x509_subject = tls_cert_construct_subject_name(csr_cert, cert_request_info)

    extended_key_usage_oids = []
    for purpose in purposes:
        if purpose == "server_auth":
            extended_key_usage_oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if purpose == "client_auth":
            extended_key_usage_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)

    return (
        x509.CertificateBuilder()
        .subject_name(x509_subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr_cert.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((datetime.now(timezone.utc)) - delta)
        .not_valid_after((datetime.now(timezone.utc)) + timedelta(days=lifetime))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(extended_key_usage_oids),
            critical=False,
        )
        .add_extension(
            x509.CertificatePolicies([PolicyInformation(ObjectIdentifier("2.23.140.1.2.1"), None)]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr_cert.public_key()),
            critical=False,
        )
    )


def ca_kms_sign_tls_certificate_request(
    cert_request_info,
    ca_cert,
    kms_key_id,
    kms_signing_algorithm="RSASSA_PKCS1_V1_5_SHA_256",
):
    csr_cert = cert_request_info["CsrCert"]
    x509_dns_names = cert_request_info["x509Sans"]
    lifetime = cert_request_info["Lifetime"]

    # reduce lifetime to maximum allowed if needed
    lifetime = min(lifetime, max_cert_lifetime)

    delta = timedelta(minutes=5)  # time delta to avoid clock skew issues

    cert = ca_build_cert(csr_cert, ca_cert, lifetime, delta, cert_request_info)

    if len(x509_dns_names) > 0:
        cert = cert.add_extension(
            x509.SubjectAlternativeName(x509_dns_names),
            critical=False,
        )

    if public_crl == "enabled":

        # construct CRL distribution point
        crl_dp = x509.DistributionPoint(
            [UniformResourceIdentifier(f"http://{domain}/{ca_name('issuing')}.crl")],
            relative_name=None,
            reasons=None,
            crl_issuer=None,
        )

        # construct Authority Information Access
        aia = x509.AuthorityInformationAccess(
            [
                AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    UniformResourceIdentifier(f"http://{domain}/{ca_name('issuing')}.crt"),
                )
            ]
        )
        cert = cert.add_extension(x509.CRLDistributionPoints([crl_dp]), critical=False)
        cert = cert.add_extension(aia, critical=False)

    cert = cert.sign(
        crypto_select_class(kms_signing_algorithm)(kms_key_id, crypto_hash_algorithm(kms_signing_algorithm)),
        crypto_hash_class(kms_signing_algorithm),
    )

    print(f"certificate serial number {cert.serial_number} issued for {cert.subject}")

    return cert.public_bytes(serialization.Encoding.PEM)


def ca_bundle_name():
    """Returns CA bundle name for uploading to S3"""
    if env_name in ["prd", "prod"]:
        return f"{project}-ca-bundle"
    return f"{project}-ca-bundle-{env_name}"


def ca_create_root_ca(public_key, private_key, kms_signing_algorithm="RSASSA_PKCS1_V1_5_SHA_256"):
    """Creates Root CA self-signed certificate with defined private key"""

    # get Root CA info
    path_length_constraint = root_ca_info.get("pathLengthConstraint")
    lifetime = root_ca_info.get("lifetime") or 7300
    subject = issuer = ca_construct_subject_name(root_ca_info)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=lifetime))
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
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=path_length_constraint,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
            critical=False,
        )
        .sign(private_key, crypto_hash_class(kms_signing_algorithm))
    )

    print(f"certificate serial number {cert.serial_number} issued for {cert.subject}")

    return cert.public_bytes(serialization.Encoding.PEM)


def ca_create_kms_root_ca(public_key, kms_key_id, kms_signing_algorithm="RSASSA_PKCS1_V1_5_SHA_256"):
    """Creates Root CA self-signed certificate with private key in KMS"""
    private_key = crypto_select_class(kms_signing_algorithm)(kms_key_id, crypto_hash_algorithm(kms_signing_algorithm))

    return ca_create_root_ca(public_key, private_key, kms_signing_algorithm)


def ca_get_ca_info(issuing_ca_info, root_ca_info):
    """Returns either Issuing CA info or Root CA info depending on Lambda function environment variable values"""
    if issuing_ca_info.get("commonName"):
        return issuing_ca_info

    return root_ca_info


def ca_kms_publish_crl(  # pylint:disable=too-many-locals
    ca_key_info,
    time_delta,
    revoked_certs,
    crl_number,
    kms_signing_algorithm="RSASSA_PKCS1_V1_5_SHA_256",
):
    """Publishes certificate revocation list signed by private key in KMS"""
    kms_key_id = ca_key_info["KmsKeyId"]
    public_key = ca_key_info["PublicKey"]

    ca_info = ca_get_ca_info(issuing_ca_info, root_ca_info)

    country = ca_info.get("country")
    state = ca_info.get("state")
    locality = ca_info.get("locality")
    organization = ca_info.get("organization")
    organizational_unit = ca_info.get("organizationalUnit")
    common_name = ca_info.get("commonName") or "Serverless Root CA"
    email_address = ca_info.get("emailAddress")

    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]

    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))

    if email_address:
        attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))

    if locality:
        attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

    if organizational_unit:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))

    if state:
        attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))

    issuer = x509.Name(attributes)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(x509.Name(issuer))
    builder = builder.last_update(datetime.today())
    builder = builder.next_update(datetime.today() + time_delta)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
    builder = builder.add_extension(x509.CRLNumber(crl_number), critical=False)

    for revoked_cert in revoked_certs:
        builder = builder.add_revoked_certificate(revoked_cert)

    return builder.sign(
        crypto_select_class(kms_signing_algorithm)(kms_key_id, crypto_hash_algorithm(kms_signing_algorithm)),
        crypto_hash_class(kms_signing_algorithm),
    )


def ca_client_tls_cert_signing_request(private_key, csr_info, kms_signing_algorithm="RSASSA_PKCS1_V1_5_SHA_256"):

    # get CSR info, using Issuing CA info if needed
    country = csr_info.get("country") or issuing_ca_info.get("country")
    state = csr_info.get("state") or issuing_ca_info.get("state")
    locality = csr_info.get("locality") or issuing_ca_info.get("locality")
    organization = csr_info.get("organization") or issuing_ca_info.get("organization")
    organizational_unit = csr_info.get("organizationalUnit")
    common_name = csr_info.get("commonName")
    email_address = csr_info.get("emailAddress")

    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]

    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))

    if email_address:
        attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))

    if locality:
        attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

    if organizational_unit:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))

    if state:
        attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))

    subject = x509.Name(attributes)

    if domain_validator(common_name):
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(subject),
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(common_name),
                    ]
                ),
                critical=False,
            )
            .sign(private_key, crypto_hash_class(kms_signing_algorithm))
        )

    else:
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(subject),
            )
            .sign(private_key, crypto_hash_class(kms_signing_algorithm))
        )

    return csr.public_bytes(serialization.Encoding.PEM)
