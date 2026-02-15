from validators import domain as domain_validator
from validators import email as email_validator
from validators import url as url_validator
from cryptography import x509
from cryptography.x509.oid import NameOID
from typing import Optional, Union
from dataclasses import dataclass, field
import ipaddress


def get_subject_attribute_or_none(x509_subject, attribute):
    if x509_subject.get_attributes_for_oid(attribute):
        return x509_subject.get_attributes_for_oid(attribute)[0].value
    return None


@dataclass
class Subject:
    common_name: str
    locality: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    email_address: Optional[str] = None

    def x509_name(self):
        attributes = [x509.NameAttribute(NameOID.COMMON_NAME, self.common_name)]

        if self.country:
            attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, self.country))

        if self.email_address:
            attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.email_address))

        if self.locality:
            attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality))

        if self.organization:
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization))

        if self.organizational_unit:
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizational_unit))

        if self.state:
            attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state))

        return x509.Name(attributes)

    @staticmethod
    def from_x509_subject(x509_subject: x509.Name):
        common_name = x509_subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        subject = Subject(common_name)
        subject.country = get_subject_attribute_or_none(x509_subject, NameOID.COUNTRY_NAME)
        subject.email_address = get_subject_attribute_or_none(x509_subject, NameOID.EMAIL_ADDRESS)
        subject.locality = get_subject_attribute_or_none(x509_subject, NameOID.LOCALITY_NAME)
        subject.state = get_subject_attribute_or_none(x509_subject, NameOID.STATE_OR_PROVINCE_NAME)
        subject.organization = get_subject_attribute_or_none(x509_subject, NameOID.ORGANIZATION_NAME)
        subject.organizational_unit = get_subject_attribute_or_none(x509_subject, NameOID.ORGANIZATIONAL_UNIT_NAME)

        return subject


def filter_and_validate_purposes(purposes: list[str]) -> list[str]:
    _purposes = list(filter(lambda x: x in ["client_auth", "server_auth"], purposes))

    # if purposes list is empty, default to client auth
    if not _purposes:
        _purposes = ["client_auth"]

    return _purposes


# Valid extended key usage values based on AWS Private CA
VALID_EXTENDED_KEY_USAGES = [
    "TLS_WEB_SERVER_AUTHENTICATION",
    "TLS_WEB_CLIENT_AUTHENTICATION",
    "CODE_SIGNING",
    "EMAIL_PROTECTION",
    "TIME_STAMPING",
    "OCSP_SIGNING",
    "IPSEC_END_SYSTEM",
    "IPSEC_TUNNEL",
    "IPSEC_USER",
    "ANY",
    "NONE",
]


def filter_and_validate_extended_key_usages(extended_key_usages: list[str]) -> list[str]:
    if extended_key_usages is None:
        return []

    _extended_key_usages = []
    for eku in extended_key_usages:
        if eku in VALID_EXTENDED_KEY_USAGES:
            _extended_key_usages.append(eku)
        elif eku.startswith("1.") or eku.startswith("2."):
            # Allow custom OIDs (format: numbers separated by periods)
            _extended_key_usages.append(eku)
        else:
            print(f"Invalid extended key usage {eku} excluded")

    return _extended_key_usages


def filter_and_validate_sans(common_name: str, sans: list[str]) -> list[str]:
    valid_common_name = domain_validator(common_name)
    _sans = sans

    # no SANs and common name is not a valid domain
    if (_sans is None or _sans == []) and not valid_common_name:
        _sans = []

    # no SANs and common name is a valid domain
    if (_sans is None or _sans == []) and valid_common_name:
        _sans = [common_name]

    # log invalid SANs
    for san in _sans:
        # allow wildcard SANs provided base domain is valid
        if san.split(".")[0] == "*" and domain_validator(san[2:]):
            continue
        # log invalid SANs
        if not domain_validator(san):
            print(f"Invalid domain {san} excluded from SANs")

    # remove invalid SANs
    _sans = [s for s in _sans if domain_validator(s) or s.split(".")[0] == "*" and domain_validator(s[2:])]

    return _sans


# Valid SAN types
VALID_SAN_TYPES = ["DNS_NAME", "IP_ADDRESS", "EMAIL_ADDRESS", "URL", "DN"]


def validate_dns_name(value: str) -> bool:
    """Validate a DNS name, including wildcards"""
    if value.split(".")[0] == "*" and domain_validator(value[2:]):
        return True
    return bool(domain_validator(value))


def validate_ip_address(value: str) -> bool:
    """Validate an IP address (IPv4 or IPv6)"""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_email_address(value: str) -> bool:
    """Validate an email address"""
    return bool(email_validator(value))


def validate_url(value: str) -> bool:
    """Validate a URL"""
    return bool(url_validator(value))


def validate_dn(value: str) -> bool:
    """Validate a Distinguished Name (basic validation - must contain at least CN=)"""
    # Basic validation: DN should have at least one attribute
    if not value or "=" not in value:
        return False
    # Check for common DN attributes
    valid_prefixes = ["CN=", "O=", "OU=", "C=", "ST=", "L=", "E=", "DC="]
    return any(attr in value.upper() for attr in valid_prefixes)


def validate_san_value(san_type: str, value: str) -> bool:
    """Validate a SAN value based on its type"""
    validators = {
        "DNS_NAME": validate_dns_name,
        "IP_ADDRESS": validate_ip_address,
        "EMAIL_ADDRESS": validate_email_address,
        "URL": validate_url,
        "DN": validate_dn,
    }
    validator = validators.get(san_type)
    if validator:
        return validator(value)
    return False


def normalize_sans_input(common_name: str, sans_input: Union[None, str, list, dict]) -> list[dict[str, str]]:
    """
    Normalize SANs input to a consistent format: list of dicts with 'type' and 'value' keys.

    Supports:
    - None: Use common_name as DNS_NAME if valid
    - str: Single DNS name
    - list[str]: List of DNS names (backwards compatible)
    - list[dict]: List of {'type': ..., 'value': ...} entries
    - dict: Map of type -> value or type -> [values]
    """
    if sans_input is None:
        # No SANs provided - use common name if it's a valid domain
        if domain_validator(common_name):
            return [{"type": "DNS_NAME", "value": common_name}]
        return []

    if isinstance(sans_input, str):
        # Single string - treat as DNS name
        return [{"type": "DNS_NAME", "value": sans_input}]

    if isinstance(sans_input, list):
        if not sans_input:
            # Empty list - use common name if valid
            if domain_validator(common_name):
                return [{"type": "DNS_NAME", "value": common_name}]
            return []

        # Check if it's a list of strings (backwards compatible) or list of dicts
        if all(isinstance(item, str) for item in sans_input):
            # List of strings - treat all as DNS names
            return [{"type": "DNS_NAME", "value": s} for s in sans_input]

        if all(isinstance(item, dict) for item in sans_input):
            # List of dicts - normalize to consistent format
            normalized = []
            for item in sans_input:
                san_type = item.get("type", "DNS_NAME").upper()
                value = item.get("value")
                if san_type and value:
                    normalized.append({"type": san_type, "value": value})
            return normalized

    if isinstance(sans_input, dict):
        # Dict format: {"DNS_NAME": ["example.com"], "IP_ADDRESS": "192.168.1.1"}
        normalized = []
        for san_type, values in sans_input.items():
            san_type_upper = san_type.upper()
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                for value in values:
                    normalized.append({"type": san_type_upper, "value": value})
        return normalized

    return []


def filter_and_validate_sans_typed(common_name: str, sans_input: Union[None, str, list, dict]) -> list[dict[str, str]]:
    """
    Filter and validate SANs input, returning a list of validated SANs with their types.
    Invalid SANs are logged and excluded.
    """
    normalized = normalize_sans_input(common_name, sans_input)
    validated = []

    for san in normalized:
        san_type = san.get("type", "DNS_NAME")
        value = san.get("value", "")

        if san_type not in VALID_SAN_TYPES:
            print(f"Invalid SAN type {san_type} excluded")
            continue

        if validate_san_value(san_type, value):
            validated.append({"type": san_type, "value": value})
        else:
            print(f"Invalid {san_type} value '{value}' excluded from SANs")

    return validated


@dataclass
class CsrInfo:
    subject: Subject
    lifetime: int = 30

    sans: Union[None, str, list, dict] = field(init=True, repr=True, default=None)
    _sans: Union[None, str, list, dict] = field(init=False, repr=False, default=None)

    purposes: list[str] = field(init=True, repr=True, default_factory=list)
    _purposes: list[str] = field(init=False, repr=False)

    extended_key_usages: list[str] = field(init=True, repr=True, default_factory=list)
    _extended_key_usages: list[str] = field(init=False, repr=False)

    @property
    def sans(self) -> list[dict[str, str]]:  # noqa: F811
        return filter_and_validate_sans_typed(self.subject.common_name, self._sans)

    @sans.setter
    def sans(self, _sans: Union[None, str, list, dict]) -> None:
        self._sans = _sans

    @property
    def purposes(self) -> list[str]:  # noqa: F811
        if isinstance(self._purposes, list):
            return filter_and_validate_purposes(self._purposes)
        return ["client_auth"]

    @purposes.setter
    def purposes(self, _purposes: list[str]) -> None:
        self._purposes = _purposes

    @property
    def extended_key_usages(self) -> list[str]:  # noqa: F811
        if isinstance(self._extended_key_usages, list):
            return filter_and_validate_extended_key_usages(self._extended_key_usages)
        return []

    @extended_key_usages.setter
    def extended_key_usages(self, _extended_key_usages: list[str]) -> None:
        self._extended_key_usages = _extended_key_usages
