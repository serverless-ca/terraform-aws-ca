import boto3
from cryptography.hazmat.primitives._asymmetric import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes


class AWSKMSEllipticCurvePrivateKey(ec.EllipticCurvePrivateKey):
    """class for AWS KMS Elliptic Curve Private Key to be used with cryptography library"""

    signature_algorithm_lookup = {
        "sha256": "ECDSA_SHA_256",
        "sha384": "ECDSA_SHA_384",
        "sha512": "ECDSA_SHA_512",
    }

    _evp_pkey = None

    def __init__(self, keyid, hash_algorithm="sha256"):
        self.keyid = keyid
        self.hash_algorithm = hash_algorithm

    @property
    def key_size(self) -> int:
        raise NotImplementedError("Key Size is not implemented")

    def exchange(self, algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
        raise NotImplementedError("Exchange not supported")

    def public_key(self) -> ec.EllipticCurvePublicKey:
        return AWSKMSEllipticCurvePublicKey(self.keyid)

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        raise NotImplementedError("Private Numbers not supported")

    def private_bytes(
        self,
        encoding,
        format,  # pylint:disable=redefined-builtin
        encryption_algorithm,
    ) -> bytes:
        raise NotImplementedError("Private Bytes not supported")

    @property
    def curve(self):
        pass

    def signer(self):
        pass

    def sign(
        self,
        data: bytes,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        # Send data to AWS KMS to be signed
        signature_algorithm.name = self.hash_algorithm
        try:
            sig_alg_str = self.signature_algorithm_lookup[signature_algorithm.name]
        except KeyError as exc:
            raise NotImplementedError(f"Unknown Signature Algorithm: {format(signature_algorithm.name)}") from exc
        client = boto3.client("kms")
        sign_response = client.sign(KeyId=self.keyid, SigningAlgorithm=sig_alg_str, Message=data)

        return sign_response["Signature"]


class AWSKMSEllipticCurvePublicKey(AWSKMSEllipticCurvePrivateKey):
    """subclass for AWS KMS ECDSA Public Key to be used with AWSKMSEllipticCurvePrivateKey superclass"""

    def __init__(self, keyid, hash_algorithm="sha256"):
        self.keyid = keyid
        self.hash_algorithm = hash_algorithm
        super(AWSKMSEllipticCurvePrivateKey, self).__init__()

    def verify(
        self,
        signature: bytes,
        data: bytes,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> None:
        raise NotImplementedError("Verify not supported")

    @property
    def key_size(self) -> int:
        raise NotImplementedError("Key size not supported")

    def public_numbers(self) -> ec.EllipticCurvePublicNumbers:
        raise NotImplementedError("Public Numbers not supported")

    def public_key(self) -> ec.EllipticCurvePublicKey:
        raise NotImplementedError("Public Key not supported")

    def public_bytes(
        self,
        encoding,  # pylint:disable=unused-argument
        format,  # pylint:disable=redefined-builtin unused-argument
    ) -> bytes:
        client = boto3.client("kms")
        public_key_response = client.get_public_key(KeyId=self.keyid)

        return public_key_response["PublicKey"]


class AWSKMSRSAPrivateKey(rsa.RSAPrivateKey):
    """class for AWS KMS RSA Private Key to be used with cryptography library for CSR generation"""

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        pass

    signature_algorithm_lookup = {
        "sha256": "RSASSA_PKCS1_V1_5_SHA_256",
        "sha384": "RSASSA_PKCS1_V1_5_SHA_384",
        "sha512": "RSASSA_PKCS1_V1_5_SHA_512",
    }

    _evp_pkey = None

    def __init__(self, keyid, hash_algorithm="sha256"):
        self.keyid = keyid
        self.hash_algorithm = hash_algorithm

    @property
    def key_size(self) -> int:
        raise NotImplementedError("Key Size is not implemented")

    def private_numbers(self) -> rsa.RSAPrivateNumbers:
        raise NotImplementedError("Private Numbers not supported")

    def private_bytes(
        self,
        encoding,
        format,  # pylint:disable=redefined-builtin
        encryption_algorithm,
    ) -> bytes:
        raise NotImplementedError("Private Bytes not supported")

    def signer(self):
        pass

    def public_key(self) -> rsa.RSAPublicKey:
        return AWSKMSRSAPublicKey(self.keyid)

    def sign(
        self,
        data: bytes,
        padding: rsa.AsymmetricPadding,
        algorithm: hashes.HashAlgorithm,
    ) -> bytes:
        algorithm.name = "sha256"

        try:
            sig_alg_str = self.signature_algorithm_lookup[algorithm.name]
        except KeyError as exc:
            raise NotImplementedError(f"Unknown Signature Algorithm: {format(algorithm.name)}") from exc
        client = boto3.client("kms")
        sign_response = client.sign(KeyId=self.keyid, SigningAlgorithm=sig_alg_str, Message=data)

        return sign_response["Signature"]


class AWSKMSRSAPublicKey(AWSKMSRSAPrivateKey):
    """subclass for AWS KMS RSA Public Key to be used with AWSKMSRSAPrivateKey superclass"""

    def __init__(self, keyid, hash_algorithm="sha256"):
        self.keyid = keyid
        self.hash_algorithm = hash_algorithm
        super(AWSKMSRSAPrivateKey, self).__init__()

    def encrypt(self, plaintext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError("Encrypt not supported")

    def verify(
        self,
        signature: bytes,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: hashes.HashAlgorithm,
    ) -> None:
        raise NotImplementedError("Verify not supported")

    @property
    def key_size(self) -> int:
        raise NotImplementedError("Key size not supported")

    def public_numbers(self) -> rsa.RSAPublicNumbers:
        raise NotImplementedError("Public Numbers not supported")

    def public_key(self) -> rsa.RSAPublicKey:
        raise NotImplementedError("Public Key not supported")

    def public_bytes(
        self,
        encoding,  # pylint:disable=unused-argument
        format,  # pylint:disable=redefined-builtin unused-argument
    ) -> bytes:
        client = boto3.client("kms")
        public_key_response = client.get_public_key(KeyId=self.keyid)

        return public_key_response["PublicKey"]
