# Feasibility Assessment: Post-Quantum Cryptography (ML-DSA) Support

* Status: draft for review
* Date: 10 August 2026
* Scope: supporting AWS KMS ML-DSA key specs (`ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`) for the
  root CA and issuing CA, e.g. an ML-DSA-65 root CA with an ML-DSA-44 issuing CA

## Verdict

**Feasible with moderate effort.** All hard prerequisites are now in place:

* AWS KMS supports ML-DSA key pairs (FIPS 204) with the `ML_DSA_SHAKE_256` signing algorithm,
  in Europe (London) and other commercial regions.
* `cryptography` 50.0.0 — already the pinned version in this repository — fully supports
  ML-DSA X.509 issuance: certificate, CSR and CRL signing, ML-DSA public keys in
  certificates, and chain verification.
* The repository's KMS signing architecture (a Python shim class whose `sign()` method calls
  the KMS `Sign` API) carries over to ML-DSA. This was verified against the `cryptography`
  50.x source: the X.509 signing path recognises any subclass of the ML-DSA private key ABCs
  and calls its `sign(data)` method with the full TBS DER bytes
  (`src/rust/src/x509/sign.rs`, `identify_key_type` and the `KeyType::MlDsa*` arm that calls
  `private_key.sign(data)`).
* The 4,096-byte KMS `RAW` message limit (which today is worked around for large CRLs using
  `MessageType="DIGEST"`, not available for ML-DSA) is solved by KMS `EXTERNAL_MU` signing
  combined with `cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher` (added in
  `cryptography` 50.0.0). Signatures produced via external mu are byte-identical to `RAW`
  signatures.

The mixed-level chain in scope — **root CA ML_DSA_65 signing an issuing CA with an ML_DSA_44
key** — is a standard X.509 construction (RFC 9881) and is supported by both KMS and
`cryptography`; the two CA key specs are already independently configurable via
`root_ca_key_spec` and `issuing_ca_key_spec`.

The main open risks are ecosystem-side, not CA-side: consumers of issued certificates
(AWS ALB/API Gateway/CloudFront mTLS, IAM Roles Anywhere, older TLS stacks) mostly do not
yet accept ML-DSA certificates, and the `certvalidator` library used in integration tests
cannot parse them.

## 1. Background

* **FIPS 204** standardises ML-DSA (Module-Lattice Digital Signature Algorithm), NIST's
  primary post-quantum signature standard.
* **RFC 9881** defines the use of ML-DSA in X.509 certificates (signature algorithm OIDs
  `2.16.840.1.101.3.4.3.17/.18/.19` and subject public key encoding).
* CA hierarchies are a priority for PQC migration: CA certificates are long-lived, and their
  signatures must remain trustworthy against "harvest now, forge later" adversaries with
  future quantum computers.

### ML-DSA parameter sets

| Key spec | NIST security category | Public key | Signature |
|---|---|---|---|
| ML_DSA_44 | 2 (~AES-128) | 1,312 B | 2,420 B |
| ML_DSA_65 | 3 (~AES-192) | 1,952 B | 3,309 B |
| ML_DSA_87 | 5 (~AES-256) | 2,592 B | 4,627 B |

For comparison, a P-256 ECDSA certificate today has a ~91-byte SPKI and ~72-byte signature.
A fully post-quantum issuing CA certificate (ML-DSA-44 subject key, ML-DSA-65 signature)
will be roughly 5–6 KB; an end-entity certificate with a classical (EC) subject key signed
by an ML-DSA-44 issuing CA roughly 3 KB. CRLs grow by one signature (2.4–4.6 KB) plus
nothing per entry. S3, DynamoDB (400 KB item limit) and GitOps storage are unaffected in
practice.

## 2. AWS KMS ML-DSA capability (verified)

* **Launch:** generally available 13 June 2025, initially US West (N. California) and
  Europe (Milan), with the remaining commercial regions following — now including
  **Europe (London), eu-west-2** (confirm in the target account with
  `aws kms create-key --key-spec ML_DSA_65 --key-usage SIGN_VERIFY --region eu-west-2`
  before committing to a region).
* **Key specs:** `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`, key usage `SIGN_VERIFY` only.
* **Signing algorithm:** a single algorithm, `ML_DSA_SHAKE_256`, for all three specs.
  `DescribeKey` returns `SigningAlgorithms: ["ML_DSA_SHAKE_256"]`.
* **Message types:**
  * `RAW` — message up to 4,096 bytes; KMS runs pure ML-DSA over the message.
  * `EXTERNAL_MU` — caller supplies the 64-byte message representative µ (FIPS 204 §6.2),
    computed over the message and bound to the public key. Signatures are identical to
    `RAW` for the same message and key. This is *not* pre-hash ML-DSA (HashML-DSA,
    FIPS 204 §5.4); there is no `DIGEST` message type for ML-DSA.
* **Keys are generated and used in FIPS 140-3 Security Level 3 validated HSMs**, matching
  the existing security story for RSA/ECDSA CA keys.
* **GetPublicKey** returns a DER `SubjectPublicKeyInfo` that `cryptography`'s
  `load_der_public_key()` (48.0+) loads as an `MLDSA{44,65,87}PublicKey`.
* **Pricing:** $1/month per key (unchanged); ML-DSA `Sign` requests are billed in the
  asymmetric request tier (~$0.15 per 10,000 — verify current rate on the KMS pricing
  page). No material change to the ~$50/year CA running cost.
* **Not supported:** ML-DSA under `GenerateDataKeyPair` (relevant to the no-CSR subject key
  flow — see §6.3), key import (BYOK), and multi-region considerations should be checked if
  ever needed.

## 3. pyca/cryptography ML-DSA capability (verified against local source)

Timeline (from the local `pyca/cryptography` checkout, `CHANGELOG.rst`):

| Version | Date | ML-DSA capability |
|---|---|---|
| 47.0.0 | 2026-04-24 | `mldsa` module (sign/verify, serialization) — AWS-LC/BoringSSL builds only |
| 48.0.0 | 2026-05-04 | ML-DSA with OpenSSL 3.5+ → **available in the standard PyPI wheels** (wheels ship OpenSSL 4.x statically, so it also works in Lambda) |
| 49.0.0 | 2026-06-12 | **X.509 signing**: `CertificateBuilder` / `CertificateSigningRequestBuilder` / `CertificateRevocationListBuilder` `.sign()` with ML-DSA keys (`algorithm=None`); ML-DSA `SignatureAlgorithmOID`s; loading certificates with ML-DSA public keys; `sign_mu` / `verify_mu` |
| 50.0.0 | 2026-07-31 | `MLDSAMuHasher` (incremental µ computation); X.509 **verification** APIs accept ML-DSA chains by default (RFC 9881) and are now API-stable |

The repository already pins `cryptography==50.0.0` in every Lambda `requirements.txt`,
`requirements-dev.txt` and `utils/requirements.txt`, so **no dependency upgrade is needed**.

Key API facts confirmed in the local source/docs:

* `MLDSA44/65/87PrivateKey` and `...PublicKey` are `abc.ABCMeta` classes → they can be
  subclassed by a KMS-backed shim, exactly like the existing
  `AWSKMSEllipticCurvePrivateKey` / `AWSKMSRSAPrivateKey` classes.
* The Rust X.509 signing path (`src/rust/src/x509/sign.rs`) identifies the key type via
  `isinstance` against those ABCs (so a shim subclass is recognised) and then invokes
  **`private_key.sign(data)`** where `data` is the full TBS DER. The shim therefore
  receives everything it needs to call KMS.
* `sign()` for ML-DSA takes no hash algorithm and no padding: builders must be called as
  `.sign(private_key, None)`. The `AlgorithmIdentifier` (e.g. `id-ml-dsa-65`) is written
  by `cryptography` from the key type; the KMS signing algorithm string plays no part in
  the certificate encoding.
* `MLDSAMuHasher(public_key).update(tbs_der).finalize()` yields the 64-byte µ accepted by
  KMS `Sign` with `MessageType="EXTERNAL_MU"`.

## 4. Current architecture and where it touches signing

Certificate issuance uses `cryptography`'s builders with KMS-backed shim key classes — TBS
bytes are never assembled by hand, which keeps the ML-DSA change surface small:

* `modules/terraform-aws-ca-lambda/utils/certs/crypto_kms_classes.py` — shim classes
  subclassing `ec.EllipticCurvePrivateKey` / `rsa.RSAPrivateKey`; `sign()` hashes locally
  and calls KMS with `MessageType="DIGEST"` (the workaround for the 4,096-byte `RAW` limit
  on large CRLs, issue #606).
* `modules/terraform-aws-ca-lambda/utils/certs/crypto.py:183-214` — three lookup functions
  (`crypto_select_class`, `crypto_hash_algorithm`, `crypto_hash_class`) mapping the KMS
  signing-algorithm string (obtained at runtime from `kms:DescribeKey`, never from
  configuration) to shim class and hash. `ML_DSA_SHAKE_256` currently raises
  `ValueError` at `crypto.py:190` — the first deterministic failure point.
* `modules/terraform-aws-ca-lambda/utils/certs/ca.py` — five `.sign()` call sites (root CA
  self-sign, issuing CA CSR + certificate, end-entity certificate, CRL), all passing a hash
  class; ML-DSA requires `None`.
* `modules/terraform-aws-ca-lambda/lambda_code/tls_cert/tls_cert.py:105-114` —
  `select_csr_crypto()` has a two-way ECC/RSA branch that would silently fall through to
  `RSA_2048` for an ML-DSA issuing CA.
* Terraform: `variables.tf:147-163` (`issuing_ca_key_spec`) and `:276-292`
  (`root_ca_key_spec`) validation lists, plus the KMS submodule's
  `modules/terraform-aws-ca-kms/variables.tf:27-45` list and the RSA-vs-ECDSA description
  label at `modules/terraform-aws-ca-kms/locals.tf:2`. The key spec does **not** flow into
  Lambda environment variables — Lambdas discover the algorithm via `DescribeKey` — so no
  Terraform→Lambda plumbing changes are needed.
* IAM policy templates grant `kms:Sign` / `kms:GetPublicKey` / `kms:DescribeKey` without a
  `kms:SigningAlgorithm` condition, so IAM does not block ML-DSA.
* Provider constraint is `aws >= 6.0` (lockfile 6.36.0); current provider versions accept
  the `ML_DSA_*` key specs on `aws_kms_key` (the Terraform registry documents them as valid
  `customer_master_key_spec` values). Pin/verify the actual minimum during implementation.
* boto3: Lambdas use the runtime-provided SDK; botocore has shipped the ML-DSA enums since
  mid-2025 and does not enforce enum membership client-side, so SDK version risk is low.
  Dev/test pins (`boto3==1.43.62`) already support ML-DSA.

## 5. Proposed design

### 5.1 New shim class

Add `AWSKMSMLDSAPrivateKey` (one class parameterised by variant, or three thin subclasses of
`MLDSA44PrivateKey` / `MLDSA65PrivateKey` / `MLDSA87PrivateKey` — subclassing the correct
ABC per variant is required so `identify_key_type` picks the right OID):

```python
class AWSKMSMLDSA65PrivateKey(mldsa.MLDSA65PrivateKey):
    def __init__(self, kms_key_id):
        self.keyid = kms_key_id
        self._public_key = load_der_public_key(kms_get_public_key(kms_key_id))

    def public_key(self):
        return self._public_key  # a real MLDSA65PublicKey — SKI/AKI and local verify just work

    def sign(self, data, context=None):
        # X.509 signing always uses an empty context
        hasher = mldsa.MLDSAMuHasher(self._public_key)
        hasher.update(data)
        mu = hasher.finalize()
        return kms_client.sign(
            KeyId=self.keyid,
            Message=mu,
            MessageType="EXTERNAL_MU",
            SigningAlgorithm="ML_DSA_SHAKE_256",
        )["Signature"]
```

Design choices:

* **Always use `EXTERNAL_MU`** rather than branching on `len(data) <= 4096`. Signatures are
  identical, one code path covers certificates and arbitrarily large CRLs, and the repeated
  µ computation is cheap (SHAKE256 over the TBS bytes).
* `public_key()` returns the genuine pyca ML-DSA public key loaded from KMS DER, unlike the
  existing EC/RSA shims which wrap `GetPublicKey` in a custom class. This lets
  `SubjectKeyIdentifier.from_public_key()`, `AuthorityKeyIdentifier`, and any post-sign
  verification work without further shimming.
* Unimplemented ABC methods (`private_bytes`, `sign_mu`, etc.) raise `NotImplementedError`,
  mirroring the current shims.

### 5.2 Algorithm selection plumbing

* `crypto_select_class()`: add `"ML_DSA_SHAKE_256"` → select the shim variant. Because all
  three key specs share one signing-algorithm string, the variant must be chosen from
  `DescribeKey`'s `KeySpec` (`ML_DSA_44/65/87`), not from `SigningAlgorithms[0]`. This is a
  small refactor: pass the key spec (already fetched in every Lambda) alongside or instead
  of the signing algorithm.
* `crypto_hash_algorithm()` / `crypto_hash_class()`: return `None` for ML-DSA; all five
  `.sign(key, hash)` call sites in `ca.py` then work unchanged, since `cryptography`
  requires `algorithm=None` for ML-DSA (same convention it uses for Ed25519).
* The issuing-CA CSR path (`crypto_kms_ca_cert_signing_request`, and the hardcoded
  `hashes.SHA256()` at `crypto.py:239`) must likewise pass `None` when the key is ML-DSA —
  `CertificateSigningRequestBuilder.sign()` supports ML-DSA since 49.0.
* `select_csr_crypto()` in `tls_cert.py`: extend the branch (`"ML_DSA" in key_spec`) —
  interacts with the subject-key question in §6.3.

### 5.3 Terraform

* Add `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87` to the three key-spec validation lists
  (`variables.tf` ×2, KMS submodule ×1).
* Fix the cosmetic RSA/ECDSA ternary in `modules/terraform-aws-ca-kms/locals.tf:2`
  (description label) to a three-way lookup.
* New example under `examples/` (e.g. `examples/ml-dsa/`) with
  `root_ca_key_spec = "ML_DSA_65"`, `issuing_ca_key_spec = "ML_DSA_44"`.

### 5.4 Tests and CI

* Unit tests: `MLDSA*PrivateKey.generate()` works locally with the pinned wheel (no HSM or
  moto dependency), so shim tests follow the existing `test_crypto_kms_classes.py` pattern
  with a mocked KMS client — the mock can sign with a locally generated key to produce
  verifiable output.
* Integration tests: `certvalidator==0.11.1` + `oscrypto` (used in
  `utils/modules/certs/crypto.py:37-39` and `tests/test_issued_certs.py`) predate ML-DSA and
  will not parse these chains. **Migrate chain validation to
  `cryptography.x509.verification`** (API-stable and ML-DSA-enabled by default as of 50.0.0).
  This also retires the oscrypto git-pin workaround. Worth doing as an independent
  preparatory PR since it benefits the existing algorithms too.
* New GitHub Actions workflow (e.g. `ml_dsa.yml`) mirroring `ecdsa_default.yml`, deploying
  the ML-DSA example to eu-west-2.
* Client-side utils: extend `generate_key()` in `utils/modules/certs/crypto.py:133-150`
  with an `ml-dsa-44/65/87` option (pyca-generated) so `client-cert.py` / `server-cert.py`
  can request fully post-quantum end-entity certificates.

## 6. Risks, constraints and open questions

### 6.1 Ecosystem acceptance of issued certificates (main adoption risk)

The CA can issue ML-DSA certificates long before common relying parties accept them:

* **AWS managed mTLS** (ALB trust stores, API Gateway mTLS, CloudFront mTLS) and
  **IAM Roles Anywhere** — the flagship use cases in the README — must be assumed *not* to
  support ML-DSA client certificates until verified. This should be tested early, per
  service, as it determines how useful a PQ chain is in practice.
* **TLS stacks:** OpenSSL 3.5+ can verify ML-DSA chains and negotiate ML-DSA in TLS 1.3;
  browsers and older embedded stacks cannot. Java, Go (x/crypto), etc. are at varying
  stages.
* Mitigation: ML-DSA is **opt-in per CA deployment** (a new hierarchy), and a classical
  hierarchy can run in parallel. Hybrid/composite certificates (ML-DSA + ECDSA in one
  signature) are still draft-stage and not supported by pyca — explicitly out of scope.

### 6.2 One signing algorithm string for three key specs

`ML_DSA_SHAKE_256` is returned for all three key specs, so the current
"`SigningAlgorithms[0]` → class" lookup is insufficient; the key spec must be threaded
through (§5.2). Low complexity, but it touches all five Lambdas' call paths.

### 6.3 No-CSR flow subject keys

KMS `GenerateDataKeyPair` (the `tls_keygen` symmetric key flow) does not support ML-DSA
key pair specs. Options for end-entity certificates under an ML-DSA issuing CA:

1. **Classical subject keys under a PQ chain** (default `ECC_NIST_P256` subject key,
   ML-DSA chain signatures) — works today, no change; the chain is quantum-safe for
   signature forgery even though the leaf keypair is classical.
2. Generate the ML-DSA subject keypair inside the Lambda with pyca (key material transits
   Lambda memory — same trust model as the current `GenerateDataKeyPair` plaintext-key
   handling, but without the KMS HSM provenance).
3. Require the CSR flow for fully-PQ end-entity certificates (client generates its own
   ML-DSA key).

Recommendation: option 1 as the default plus option 3 documented; defer option 2.

### 6.4 CRL producer/consumer compatibility

CRL signing works via the shim (§5.1) with no size limit thanks to `EXTERNAL_MU`. But CRL
*consumers* (e.g. IAM Roles Anywhere revocation, corporate PKI tooling) must parse
ML-DSA-signed CRLs — same ecosystem caveat as §6.1.

### 6.5 Region availability

ML-DSA key specs rolled out to commercial regions from June 2025 and are available in
Europe (London); availability should still be smoke-tested in each target account/region
(and note ML-DSA is absent from some partitions, e.g. China regions use SM2).

### 6.6 Parameter-set guidance

* The chain's effective strength is its weakest link: a root at ML_DSA_65 with an issuing CA
  at ML_DSA_44 yields a category-2 (~128-bit) chain — a reasonable default trade-off of
  size vs. strength for a private CA, and the combination in scope works without caveats.
* Long-lived roots may justify ML_DSA_87 (CNSA 2.0 mandates ML-DSA-87 for national security
  systems). All three specs should be selectable independently per tier, as today.
* Mixed classical/PQ chains (e.g. ECDSA root signing an ML-DSA issuing CA, or vice versa)
  fall out of the design for free — each `.sign()` call uses that tier's own key — but each
  combination added to CI multiplies the test matrix; documenting "supported but untested"
  combinations is acceptable initially.

## 7. Suggested implementation phases

1. **Preparation (independent PR):** replace `certvalidator`/`oscrypto` chain validation in
   tests and client utils with `cryptography.x509.verification`; refresh the dev `.venv` to
   cryptography 50.x.
2. **Core (single PR):** ML-DSA shim classes + `crypto.py` selection refactor (key-spec
   driven, hash=None) + Terraform validation lists + unit tests.
3. **Integration:** `examples/ml-dsa/` + `ml_dsa.yml` workflow in eu-west-2, including CRL
   revocation round-trip verified with OpenSSL 3.5 and pyca.
4. **Client tooling & docs:** `generate_key()` ML-DSA option; docs updates
   (`docs/options.md`, `docs/faq.md`, `docs/reference.md`, `docs/security.md`); blog-style
   announcement.
5. **Later / out of scope now:** ML-DSA subject keys in the no-CSR flow, hybrid/composite
   certificates, AWS service mTLS compatibility tracking.

Rough effort: phases 1–3 are each in the "days" range; nothing requires architectural
change because the algorithm-agnostic shim + builder design absorbs ML-DSA cleanly.

## 8. References

* [FIPS 204 — Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
* [RFC 9881 — Use of ML-DSA in X.509](https://www.rfc-editor.org/rfc/rfc9881)
* [ML-DSA keys in AWS KMS (developer guide)](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html)
* [AWS KMS key spec reference (ML-DSA section)](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html#key-spec-mldsa)
* [AWS announcement: KMS ML-DSA support (June 2025)](https://aws.amazon.com/about-aws/whats-new/2025/06/aws-kms-post-quantum-ml-dsa-digital-signatures)
* [AWS blog: How to create post-quantum signatures using AWS KMS and ML-DSA](https://aws.amazon.com/blogs/security/how-to-create-post-quantum-signatures-using-aws-kms-and-ml-dsa/)
* [AWS blog: Post-quantum ML-DSA code signing with AWS Private CA and AWS KMS](https://aws.amazon.com/blogs/security/post-quantum-ml-dsa-code-signing-with-aws-private-ca-and-aws-kms/)
* [pyca/cryptography ML-DSA documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mldsa/)
* [pyca/cryptography changelog (47.0.0–50.0.0)](https://cryptography.io/en/latest/changelog/)
* [Terraform `aws_kms_key` resource (valid key specs)](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key)
