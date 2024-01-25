# from https://stackoverflow.com/questions/45410508/python-requests-ca-certificates-as-a-string

import requests
from OpenSSL.crypto import PKCS12, X509, PKey


def _is_key_file_encrypted(keyfile):
    """In memory key is not encrypted"""
    if isinstance(keyfile, PKey):
        return False
    return _is_key_file_encrypted.original(keyfile)


class PyOpenSSLContext(requests.packages.urllib3.contrib.pyopenssl.PyOpenSSLContext):
    """Support loading certs from memory"""

    def load_cert_chain(self, certfile, keyfile=None, password=None):
        if isinstance(certfile, X509) and isinstance(keyfile, PKey):
            self._ctx.use_certificate(certfile)
            self._ctx.use_privatekey(keyfile)
        else:
            super().load_cert_chain(certfile, keyfile=keyfile, password=password)


class HTTPAdapter(requests.adapters.HTTPAdapter):
    """Handle a variety of cert types"""

    def cert_verify(self, conn, url, verify, cert):
        if cert:
            # PKCS12
            if isinstance(cert, PKCS12):
                conn.cert_file = cert.get_certificate()
                conn.key_file = cert.get_privatekey()
                cert = None
            elif isinstance(cert, tuple) and len(cert) == 2:
                # X509 and PKey
                if isinstance(cert[0], X509) and hasattr(cert[1], PKey):
                    conn.cert_file = cert[0]
                    conn.key_file = cert[1]
                    cert = None
                # cryptography objects
                elif hasattr(cert[0], "public_bytes") and hasattr(cert[1], "private_bytes"):
                    conn.cert_file = X509.from_cryptography(cert[0])
                    conn.key_file = PKey.from_cryptography_key(cert[1])
                    cert = None
        super().cert_verify(conn, url, verify, cert)


def patch_requests(adapter=True):
    """You can perform a full patch and use requests as usual:

    >>> patch_requests()
    >>> requests.get('https://httpbin.org/get')

    or use the adapter explicitly:

    >>> patch_requests(adapter=False)
    >>> session = requests.Session()
    >>> session.mount('https', HTTPAdapter())
    >>> session.get('https://httpbin.org/get')
    """
    if hasattr(requests.packages.urllib3.util.ssl_, "_is_key_file_encrypted"):
        _is_key_file_encrypted.original = (
            requests.packages.urllib3.util.ssl_._is_key_file_encrypted  # pylint:disable=protected-access
        )
        requests.packages.urllib3.util.ssl_._is_key_file_encrypted = (  # pylint:disable=protected-access
            _is_key_file_encrypted
        )
    requests.packages.urllib3.util.ssl_.SSLContext = PyOpenSSLContext
    if adapter:
        requests.sessions.HTTPAdapter = HTTPAdapter
