from validators import domain as domain_validator
from validators import email as email_validator
from validators import url as url_validator
from cryptography import x509
from cryptography.x509.oid import NameOID
from typing import Optional, Union
from dataclasses import dataclass, field
import base64
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


# X.509 extension OIDs the CA emits and controls itself. Callers may only ADD new
# extensions via the "extensions" field - never one the CA manages - so all of these are
# rejected even if an operator adds one to the allowlist (the denylist always wins,
# defense in depth). Denylisting subjectAltName in particular prevents a caller from
# forging the certificate's identity; denylisting the rest prevents a caller from
# shadowing or colliding with an extension the CA is responsible for.
DENYLISTED_EXTENSION_OIDS = frozenset(
    {
        "2.5.29.14",  # subjectKeyIdentifier
        "2.5.29.15",  # keyUsage
        "2.5.29.17",  # subjectAlternativeName
        "2.5.29.19",  # basicConstraints
        "2.5.29.31",  # cRLDistributionPoints
        "2.5.29.32",  # certificatePolicies
        "2.5.29.35",  # authorityKeyIdentifier
        "2.5.29.37",  # extendedKeyUsage
        "1.3.6.1.5.5.7.1.1",  # authorityInfoAccess
    }
)


def validate_custom_extensions(extensions: list[dict], allowlist: list[str]) -> list[dict]:
    """Authorise and validate caller-supplied custom X.509 extensions.

    Each extension is a dict: {"oid": <dotted string>, "value_b64": <base64 DER>, "critical": <bool>}.

    Unlike SANs and extended key usages - which silently drop invalid entries - a custom
    extension is usually load-bearing for the requesting integration, so any rejected
    extension fails the whole request. Raises ValueError with a clear message on the first
    rejected extension. Returns the validated list unchanged on success.
    """
    seen_oids = set()
    for extension in extensions:
        oid = extension.get("oid")
        if not oid:
            raise ValueError("Custom extension is missing required field 'oid'")

        # a duplicate OID would raise an uncaught error when added to the certificate at
        # signing time, so reject it cleanly here instead
        if oid in seen_oids:
            raise ValueError(f"Custom extension OID {oid} is specified more than once")
        seen_oids.add(oid)

        # denylist always wins, even if the OID is also on the allowlist
        if oid in DENYLISTED_EXTENSION_OIDS:
            raise ValueError(f"Custom extension OID {oid} is reserved and cannot be set by callers")

        if oid not in allowlist:
            raise ValueError(f"Custom extension OID {oid} is not in the configured allowlist")

        try:
            x509.ObjectIdentifier(oid)
        except Exception as exc:  # pylint:disable=broad-except
            raise ValueError(f"Custom extension OID {oid} is not a valid object identifier") from exc

        value_b64 = extension.get("value_b64")
        if value_b64 is None:
            raise ValueError(f"Custom extension OID {oid} is missing required field 'value_b64'")

        try:
            base64.b64decode(value_b64, validate=True)
        except Exception as exc:  # pylint:disable=broad-except
            raise ValueError(f"Custom extension OID {oid} has an invalid base64 value") from exc

    return extensions


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


def _default_san_from_common_name(common_name: str) -> list[dict[str, str]]:
    """Return common name as DNS_NAME SAN if valid, otherwise empty list."""
    if domain_validator(common_name):
        return [{"type": "DNS_NAME", "value": common_name}]
    return []


def _normalize_list_of_dicts(sans_list: list[dict]) -> list[dict[str, str]]:
    """Normalize a list of dicts to consistent format."""
    normalized = []
    for item in sans_list:
        san_type = item.get("type", "DNS_NAME").upper()
        value = item.get("value")
        if san_type and value:
            normalized.append({"type": san_type, "value": value})
    return normalized


def _normalize_dict_format(sans_dict: dict) -> list[dict[str, str]]:
    """Normalize dict format: {"DNS_NAME": ["example.com"], "IP_ADDRESS": "192.168.1.1"}"""
    normalized = []
    for san_type, values in sans_dict.items():
        san_type_upper = san_type.upper()
        if isinstance(values, str):
            values = [values]
        if isinstance(values, list):
            for value in values:
                normalized.append({"type": san_type_upper, "value": value})
    return normalized


def _normalize_list_input(common_name: str, sans_list: list) -> list[dict[str, str]]:
    """Normalize list input (strings or dicts)."""
    if not sans_list:
        return _default_san_from_common_name(common_name)

    if all(isinstance(item, str) for item in sans_list):
        return [{"type": "DNS_NAME", "value": s} for s in sans_list]

    if all(isinstance(item, dict) for item in sans_list):
        return _normalize_list_of_dicts(sans_list)

    return []


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
        return _default_san_from_common_name(common_name)

    if isinstance(sans_input, str):
        return [{"type": "DNS_NAME", "value": sans_input}]

    if isinstance(sans_input, list):
        return _normalize_list_input(common_name, sans_input)

    if isinstance(sans_input, dict):
        return _normalize_dict_format(sans_input)

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

    # Caller-supplied custom X.509 extensions: list of
    # {"oid": <dotted string>, "value_b64": <base64 DER>, "critical": <bool>}.
    # Validation against the allowlist/denylist happens at signing time, not here.
    extensions: list[dict] = field(default_factory=list)

    def __post_init__(self):
        # Ensure setters are called for fields with default values
        # This is needed because dataclasses don't call setters for defaults
        self._sans = self.sans
        self._purposes = self.purposes
        self._extended_key_usages = self.extended_key_usages

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
