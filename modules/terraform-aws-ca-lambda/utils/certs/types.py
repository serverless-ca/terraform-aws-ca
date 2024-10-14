from validators import domain as domain_validator
from cryptography import x509
from cryptography.x509.oid import NameOID
from typing import Optional
from dataclasses import dataclass, field


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


def filter_and_validate_sans(common_name: str, sans: list[str]) -> list[str]:
    valid_common_name = domain_validator(common_name)
    _sans = sans

    # no SANs and common name is not a valid domain
    if (_sans is None or _sans == []) and not valid_common_name:
        _sans = []

    # no SANs and common name is a valid domain
    if (_sans is None or _sans == []) and valid_common_name:
        _sans = [common_name]

    # remove invalid SANs
    _sans = [s for s in _sans if domain_validator(s)]

    return _sans


@dataclass
class CsrInfo:
    subject: Subject
    lifetime: int = 30

    sans: list[str] = field(init=True, repr=True, default_factory=list)
    _sans: list[str] = field(init=False, repr=False)

    purposes: list[str] = field(init=True, repr=True, default_factory=list)
    _purposes: list[str] = field(init=False, repr=False)

    @property
    def sans(self) -> list[str]:  # noqa: F811
        if isinstance(self._sans, list):
            return filter_and_validate_sans(self.subject.common_name, self._sans)

        return filter_and_validate_sans(self.subject.common_name, [])

    @sans.setter
    def sans(self, _sans: list[str]) -> None:
        self._sans = _sans

    @property
    def purposes(self) -> list[str]:  # noqa: F811
        if isinstance(self._purposes, list):
            return filter_and_validate_purposes(self._purposes)
        return ["client_auth"]

    @purposes.setter
    def purposes(self, _purposes: list[str]) -> None:
        self._purposes = _purposes
