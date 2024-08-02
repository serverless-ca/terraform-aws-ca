from dataclasses import dataclass
from dataclasses_json import dataclass_json, LetterCase
from typing import Optional

# TODO: Request and Response classes use different naming convention


@dataclass_json
@dataclass
class Request:
    common_name: str
    locality: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    email_address: Optional[str] = None
    state: Optional[str] = None
    lifetime: Optional[int] = 30
    purposes: Optional[list[str]] = None
    sans: Optional[list[str]] = None
    ca_chain_only: Optional[bool] = None
    csr_file: Optional[str] = None
    force_issue: Optional[bool] = None
    cert_bundle: Optional[bool] = None
    base64_csr_data: Optional[str] = None


@dataclass_json(letter_case=LetterCase.PASCAL)
@dataclass
class CertificateResponse:
    certificate_info: dict
    base64_certificate: str
    subject: str
    base64_issuing_ca_certificate: str
    base64_root_ca_certificate: str
    base64_ca_chain: str


@dataclass_json(letter_case=LetterCase.PASCAL)
@dataclass
class CaChainResponse:
    base64_issuing_ca_certificate: str
    base64_root_ca_certificate: str
    base64_ca_chain: str
