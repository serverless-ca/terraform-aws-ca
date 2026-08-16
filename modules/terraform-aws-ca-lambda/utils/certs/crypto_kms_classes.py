import hashlib
import boto3
from cryptography.hazmat.primitives._asymmetric import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key


class AWSKMSEllipticCurvePrivateKey(ec.EllipticCurvePrivateKey):
    """class for AWS KMS Elliptic Curve Private Key to be used with cryptography library"""

    signature_algorithm_lookup = {"sha256": "ECDSA_SHA_256", "sha384": "ECDSA_SHA_384", "sha512": "ECDSA_SHA_512"}

    _evp_pkey = None

    def __init__(self, keyid, hash_algorithm="sha256"):
        self.keyid = keyid
        self.hash_algorithm = hash_algorithm

    def __copy__(self):
        return AWSKMSEllipticCurvePrivateKey(self.keyid, self.hash_algorithm)

    def __deepcopy__(self, memo):
        return AWSKMSEllipticCurvePrivateKey(self.keyid, self.hash_algorithm)

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
        # KMS Sign limits a RAW message to 4096 bytes, so hash locally and sign
        # the fixed-size digest (MessageType=DIGEST) to support larger payloads
        # such as CRLs with many revoked certificates (issue #606).
        digest = hashlib.new(self.hash_algorithm, data).digest()
        sign_response = client.sign(
            KeyId=self.keyid, SigningAlgorithm=sig_alg_str, Message=digest, MessageType="DIGEST"
        )

        return sign_response["Signature"]


class AWSKMSEllipticCurvePublicKey(AWSKMSEllipticCurvePrivateKey):
    """subclass for AWS KMS ECDSA Public Key to be used with AWSKMSEllipticCurvePrivateKey superclass"""

    def __init__(self, keyid, hash_algorithm="sha256"):
        self.keyid = keyid
        self.hash_algorithm = hash_algorithm
        super(AWSKMSEllipticCurvePrivateKey, self).__init__()

    def __copy__(self):
        return AWSKMSEllipticCurvePublicKey(self.keyid, self.hash_algorithm)

    def __deepcopy__(self, memo):
        return AWSKMSEllipticCurvePublicKey(self.keyid, self.hash_algorithm)

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

    def __copy__(self):
        return AWSKMSRSAPrivateKey(self.keyid, self.hash_algorithm)

    def __deepcopy__(self, memo):
        return AWSKMSRSAPrivateKey(self.keyid, self.hash_algorithm)

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

    def sign(self, data: bytes, padding: rsa.AsymmetricPadding, algorithm: hashes.HashAlgorithm) -> bytes:
        algorithm.name = "sha256"

        try:
            sig_alg_str = self.signature_algorithm_lookup[algorithm.name]
        except KeyError as exc:
            raise NotImplementedError(f"Unknown Signature Algorithm: {format(algorithm.name)}") from exc
        client = boto3.client("kms")
        # KMS Sign limits a RAW message to 4096 bytes, so hash locally and sign
        # the fixed-size digest (MessageType=DIGEST) to support larger payloads
        # such as CRLs with many revoked certificates (issue #606).
        digest = hashlib.new(algorithm.name, data).digest()
        sign_response = client.sign(
            KeyId=self.keyid, SigningAlgorithm=sig_alg_str, Message=digest, MessageType="DIGEST"
        )

        return sign_response["Signature"]


class AWSKMSMLDSAPrivateKeyMixin:
    """Shared implementation for AWS KMS ML-DSA (FIPS 204) private keys used with the
    cryptography library. Concrete subclasses bind the correct parameter set ABC so that
    X.509 signing writes the matching AlgorithmIdentifier (id-ml-dsa-44/65/87, RFC 9881).

    Signing always uses KMS MessageType=EXTERNAL_MU: the 64-byte message representative
    mu is computed locally over data of any size, avoiding the 4096-byte KMS RAW message
    limit (e.g. CRLs with many revoked certificates). Signatures produced via external
    mu are identical to KMS RAW signatures for the same message and key.
    """

    def __init__(self, keyid, hash_algorithm=None):
        # hash_algorithm is accepted for interface compatibility with the EC and RSA
        # key classes but unused: ML-DSA signs the message directly without a pre-hash
        self.keyid = keyid
        self.hash_algorithm = hash_algorithm
        self._public_key = None

    def __copy__(self):
        return type(self)(self.keyid)

    def __deepcopy__(self, memo):
        return type(self)(self.keyid)

    def public_key(self):
        """Returns the genuine cryptography ML-DSA public key loaded from KMS DER"""
        if self._public_key is None:
            client = boto3.client("kms")
            public_key_der = client.get_public_key(KeyId=self.keyid)["PublicKey"]
            self._public_key = load_der_public_key(public_key_der)

        return self._public_key

    def sign(self, data: bytes, context=None) -> bytes:
        # X.509 signing always uses an empty context string
        if context:
            raise NotImplementedError("ML-DSA context strings are not supported for KMS signing")

        hasher = mldsa.MLDSAMuHasher(self.public_key())
        hasher.update(data)

        return self.sign_mu(hasher.finalize())

    def sign_mu(self, mu: bytes) -> bytes:
        client = boto3.client("kms")
        sign_response = client.sign(
            KeyId=self.keyid, SigningAlgorithm="ML_DSA_SHAKE_256", Message=mu, MessageType="EXTERNAL_MU"
        )

        return sign_response["Signature"]

    def private_bytes(
        self,
        encoding,
        format,  # pylint:disable=redefined-builtin
        encryption_algorithm,
    ) -> bytes:
        raise NotImplementedError("Private Bytes not supported")

    def private_bytes_raw(self) -> bytes:
        raise NotImplementedError("Private Bytes not supported")


class AWSKMSMLDSA44PrivateKey(AWSKMSMLDSAPrivateKeyMixin, mldsa.MLDSA44PrivateKey):
    """class for AWS KMS ML-DSA-44 Private Key to be used with cryptography library"""


class AWSKMSMLDSA65PrivateKey(AWSKMSMLDSAPrivateKeyMixin, mldsa.MLDSA65PrivateKey):
    """class for AWS KMS ML-DSA-65 Private Key to be used with cryptography library"""


class AWSKMSMLDSA87PrivateKey(AWSKMSMLDSAPrivateKeyMixin, mldsa.MLDSA87PrivateKey):
    """class for AWS KMS ML-DSA-87 Private Key to be used with cryptography library"""


class AWSKMSRSAPublicKey(AWSKMSRSAPrivateKey):
    """subclass for AWS KMS RSA Public Key to be used with AWSKMSRSAPrivateKey superclass"""

    def __init__(self, keyid, hash_algorithm="sha256"):
        self.keyid = keyid
        self.hash_algorithm = hash_algorithm
        super(AWSKMSRSAPrivateKey, self).__init__()

    def __copy__(self):
        return AWSKMSRSAPublicKey(self.keyid, self.hash_algorithm)

    def __deepcopy__(self, memo):
        return AWSKMSRSAPublicKey(self.keyid, self.hash_algorithm)

    def encrypt(self, plaintext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError("Encrypt not supported")

    def verify(
        self, signature: bytes, data: bytes, padding: AsymmetricPadding, algorithm: hashes.HashAlgorithm
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
