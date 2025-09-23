"""
Certificate Profile System

This module implements a flexible certificate profile system that allows
issuing certificates with specific extensions and constraints for different
use cases, such as PKINIT, TLS, etc.
"""

import os
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509 import (
    AccessDescription,
    UniformResourceIdentifier,
    PolicyInformation,
    ObjectIdentifier,
    OtherName,
    GeneralName,
)
from cryptography.x509.oid import AuthorityInformationAccessOID


@dataclass
class CertificateProfile:
    """Defines a certificate profile with specific extensions and constraints"""
    name: str
    description: str
    key_usage: Dict[str, bool] = field(default_factory=dict)
    extended_key_usage: List[str] = field(default_factory=list)
    basic_constraints: Optional[Dict[str, Any]] = None
    subject_alt_names: Optional[List[str]] = None
    certificate_policies: Optional[List[str]] = None
    crl_distribution_points: Optional[List[str]] = None
    authority_info_access: Optional[List[Dict[str, str]]] = None
    custom_extensions: Optional[List[Dict[str, Any]]] = None
    lifetime_days: Optional[int] = None
    max_lifetime_days: Optional[int] = None
    require_common_name: bool = True
    allow_wildcard_sans: bool = False


class ProfileManager:
    """Manages certificate profiles and their configurations"""
    
    def __init__(self):
        self.profiles: Dict[str, CertificateProfile] = {}
        self._load_default_profiles()
        self._load_custom_profiles()
    
    def _load_default_profiles(self):
        """Load default certificate profiles"""
        # TLS Client Profile
        self.profiles["tls_client"] = CertificateProfile(
            name="tls_client",
            description="Standard TLS client certificate",
            key_usage={
                "digital_signature": True,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
                "content_commitment": False,
                "encipher_only": False,
                "decipher_only": False,
            },
            extended_key_usage=["client_auth"],
            certificate_policies=["2.23.140.1.2.1"],  # DV Certificate Policy
            lifetime_days=365,
            max_lifetime_days=365,
        )
        
        # TLS Server Profile
        self.profiles["tls_server"] = CertificateProfile(
            name="tls_server",
            description="Standard TLS server certificate",
            key_usage={
                "digital_signature": True,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
                "content_commitment": False,
                "encipher_only": False,
                "decipher_only": False,
            },
            extended_key_usage=["server_auth"],
            certificate_policies=["2.23.140.1.2.1"],  # DV Certificate Policy
            lifetime_days=365,
            max_lifetime_days=365,
            allow_wildcard_sans=True,
        )
        
        # PKINIT KDC Profile (based on FreeIPA requirements)
        self.profiles["pkinit_kdc"] = CertificateProfile(
            name="pkinit_kdc",
            description="PKINIT KDC certificate for Kerberos authentication",
            key_usage={
                "digital_signature": True,
                "key_encipherment": False,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
                "content_commitment": False,
                "encipher_only": False,
                "decipher_only": False,
            },
            extended_key_usage=["client_auth", "server_auth"],
            certificate_policies=["1.3.6.1.5.2.3.5"],  # PKINIT KDC OID
            lifetime_days=3650,  # 10 years for KDC certificates
            max_lifetime_days=3650,
            require_common_name=True,
        )
        
        # PKINIT Client Profile
        self.profiles["pkinit_client"] = CertificateProfile(
            name="pkinit_client",
            description="PKINIT client certificate for Kerberos authentication",
            key_usage={
                "digital_signature": True,
                "key_encipherment": False,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
                "content_commitment": False,
                "encipher_only": False,
                "decipher_only": False,
            },
            extended_key_usage=["client_auth"],
            certificate_policies=["1.3.6.1.5.2.3.5"],  # PKINIT OID
            lifetime_days=365,
            max_lifetime_days=365,
            require_common_name=True,
        )
        
        # CA Profile
        self.profiles["ca"] = CertificateProfile(
            name="ca",
            description="Certificate Authority certificate",
            key_usage={
                "digital_signature": True,
                "key_encipherment": False,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": True,
                "crl_sign": True,
                "content_commitment": False,
                "encipher_only": False,
                "decipher_only": False,
            },
            basic_constraints={"ca": True, "path_length": None},
            lifetime_days=7300,  # 20 years for CA certificates
            max_lifetime_days=7300,
        )
    
    def get_profile(self, profile_name: str) -> Optional[CertificateProfile]:
        """Get a certificate profile by name"""
        return self.profiles.get(profile_name)
    
    def list_profiles(self) -> List[str]:
        """List all available profile names"""
        return list(self.profiles.keys())
    
    def add_profile(self, profile: CertificateProfile):
        """Add a custom profile"""
        self.profiles[profile.name] = profile
    
    def _load_custom_profiles(self):
        """Load custom profiles from environment variables"""
        import os
        import json
        
        profiles_json = os.environ.get("CERTIFICATE_PROFILES", "{}")
        if profiles_json:
            try:
                custom_profiles = json.loads(profiles_json)
                self.load_profiles_from_config(custom_profiles)
                print(f"Loaded {len(custom_profiles)} custom certificate profiles")
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse CERTIFICATE_PROFILES: {e}")
    
    def load_profiles_from_config(self, config: Dict[str, Any]):
        """Load profiles from configuration dictionary"""
        for profile_name, profile_config in config.items():
            profile = CertificateProfile(
                name=profile_name,
                **profile_config
            )
            self.profiles[profile_name] = profile


def create_key_usage_extension(profile: CertificateProfile) -> x509.KeyUsage:
    """Create KeyUsage extension from profile"""
    return x509.KeyUsage(
        digital_signature=profile.key_usage.get("digital_signature", False),
        key_cert_sign=profile.key_usage.get("key_cert_sign", False),
        crl_sign=profile.key_usage.get("crl_sign", False),
        content_commitment=profile.key_usage.get("content_commitment", False),
        key_encipherment=profile.key_usage.get("key_encipherment", False),
        data_encipherment=profile.key_usage.get("data_encipherment", False),
        key_agreement=profile.key_usage.get("key_agreement", False),
        encipher_only=profile.key_usage.get("encipher_only", False),
        decipher_only=profile.key_usage.get("decipher_only", False),
    )


def create_extended_key_usage_extension(profile: CertificateProfile) -> Optional[x509.ExtendedKeyUsage]:
    """Create ExtendedKeyUsage extension from profile"""
    if not profile.extended_key_usage:
        return None
    
    oids = []
    for usage in profile.extended_key_usage:
        if usage == "client_auth":
            oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        elif usage == "server_auth":
            oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
        elif usage == "code_signing":
            oids.append(ExtendedKeyUsageOID.CODE_SIGNING)
        elif usage == "email_protection":
            oids.append(ExtendedKeyUsageOID.EMAIL_PROTECTION)
        elif usage == "time_stamping":
            oids.append(ExtendedKeyUsageOID.TIME_STAMPING)
        elif usage == "ocsp_signing":
            oids.append(ExtendedKeyUsageOID.OCSP_SIGNING)
    
    return x509.ExtendedKeyUsage(oids) if oids else None


def create_basic_constraints_extension(profile: CertificateProfile) -> Optional[x509.BasicConstraints]:
    """Create BasicConstraints extension from profile"""
    if not profile.basic_constraints:
        return None
    
    return x509.BasicConstraints(
        ca=profile.basic_constraints.get("ca", False),
        path_length=profile.basic_constraints.get("path_length"),
    )


def create_certificate_policies_extension(profile: CertificateProfile) -> Optional[x509.CertificatePolicies]:
    """Create CertificatePolicies extension from profile"""
    if not profile.certificate_policies:
        return None
    
    policies = []
    for policy_oid in profile.certificate_policies:
        policies.append(PolicyInformation(ObjectIdentifier(policy_oid), None))
    
    return x509.CertificatePolicies(policies) if policies else None


def create_crl_distribution_points_extension(profile: CertificateProfile, domain: str = None) -> Optional[x509.CRLDistributionPoints]:
    """Create CRLDistributionPoints extension from profile"""
    if not profile.crl_distribution_points:
        return None
    
    distribution_points = []
    for crl_url in profile.crl_distribution_points:
        if domain and "{domain}" in crl_url:
            crl_url = crl_url.format(domain=domain)
        distribution_points.append(
            x509.DistributionPoint(
                [UniformResourceIdentifier(crl_url)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        )
    
    return x509.CRLDistributionPoints(distribution_points) if distribution_points else None


def create_authority_info_access_extension(profile: CertificateProfile, domain: str = None) -> Optional[x509.AuthorityInformationAccess]:
    """Create AuthorityInformationAccess extension from profile"""
    if not profile.authority_info_access:
        return None
    
    access_descriptions = []
    for aia in profile.authority_info_access:
        if domain and "{domain}" in aia["url"]:
            aia["url"] = aia["url"].format(domain=domain)
        
        if aia["access_method"] == "ca_issuers":
            access_descriptions.append(
                AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    UniformResourceIdentifier(aia["url"]),
                )
            )
        elif aia["access_method"] == "ocsp":
            access_descriptions.append(
                AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    UniformResourceIdentifier(aia["url"]),
                )
            )
    
    return x509.AuthorityInformationAccess(access_descriptions) if access_descriptions else None


def create_subject_alt_names_extension(profile: CertificateProfile, sans: List[str] = None) -> Optional[x509.SubjectAlternativeName]:
    """Create SubjectAlternativeName extension from profile"""
    if not profile.subject_alt_names and not sans:
        return None
    
    alt_names = []
    all_sans = (profile.subject_alt_names or []) + (sans or [])
    
    for san in all_sans:
        if san.startswith("DNS:"):
            alt_names.append(x509.DNSName(san[4:]))
        elif san.startswith("IP:"):
            alt_names.append(x509.IPAddress(san[3:]))
        elif san.startswith("EMAIL:"):
            alt_names.append(x509.RFC822Name(san[6:]))
        elif san.startswith("URI:"):
            alt_names.append(x509.UniformResourceIdentifier(san[4:]))
        else:
            # Default to DNS name
            alt_names.append(x509.DNSName(san))
    
    return x509.SubjectAlternativeName(alt_names) if alt_names else None


def create_pkinit_principal_san(principal: str) -> x509.SubjectAlternativeName:
    """Create SubjectAlternativeName extension for PKINIT principal"""
    # PKINIT requires the Kerberos principal in the SAN as an OtherName
    # OID 1.3.6.1.5.2.2 is for Kerberos principal names
    kerberos_principal_oid = ObjectIdentifier("1.3.6.1.5.2.2")
    
    # Encode the principal as UTF-8 bytes
    principal_bytes = principal.encode('utf-8')
    
    other_name = OtherName(kerberos_principal_oid, principal_bytes)
    
    return x509.SubjectAlternativeName([other_name])


def apply_profile_to_certificate_builder(
    builder: x509.CertificateBuilder,
    profile: CertificateProfile,
    domain: str = None,
    sans: List[str] = None
) -> x509.CertificateBuilder:
    """Apply profile extensions to a certificate builder"""
    
    # Key Usage (critical)
    builder = builder.add_extension(
        create_key_usage_extension(profile),
        critical=True
    )
    
    # Extended Key Usage
    ext_key_usage = create_extended_key_usage_extension(profile)
    if ext_key_usage:
        builder = builder.add_extension(ext_key_usage, critical=False)
    
    # Basic Constraints
    basic_constraints = create_basic_constraints_extension(profile)
    if basic_constraints:
        builder = builder.add_extension(basic_constraints, critical=True)
    
    # Certificate Policies
    cert_policies = create_certificate_policies_extension(profile)
    if cert_policies:
        builder = builder.add_extension(cert_policies, critical=False)
    
    # CRL Distribution Points
    crl_dp = create_crl_distribution_points_extension(profile, domain)
    if crl_dp:
        builder = builder.add_extension(crl_dp, critical=False)
    
    # Authority Information Access
    aia = create_authority_info_access_extension(profile, domain)
    if aia:
        builder = builder.add_extension(aia, critical=False)
    
    # Subject Alternative Names
    san_ext = create_subject_alt_names_extension(profile, sans)
    if san_ext:
        builder = builder.add_extension(san_ext, critical=False)
    
    return builder


# Global profile manager instance
profile_manager = ProfileManager()
