# Certificate Profiles

The serverless CA supports a flexible certificate profile system that allows issuing certificates with specific extensions and constraints for different use cases, such as PKINIT, TLS, and custom applications.

## Overview

Certificate profiles define the structure and extensions that will be included in issued certificates. This allows you to:

- Issue certificates with specific key usage and extended key usage
- Apply custom certificate policies and OIDs
- Configure CRL distribution points and authority information access
- Set appropriate certificate lifetimes for different use cases
- Add custom extensions for specialized applications

## Built-in Profiles

The serverless CA includes several built-in profiles:

### TLS Client Profile (`tls_client`)
- **Purpose**: Standard TLS client certificates
- **Key Usage**: Digital signature, key encipherment
- **Extended Key Usage**: Client authentication
- **Certificate Policy**: `2.23.140.1.2.1` (DV Certificate Policy)
- **Lifetime**: 365 days

### TLS Server Profile (`tls_server`)
- **Purpose**: Standard TLS server certificates
- **Key Usage**: Digital signature, key encipherment
- **Extended Key Usage**: Server authentication
- **Certificate Policy**: `2.23.140.1.2.1` (DV Certificate Policy)
- **Lifetime**: 365 days
- **Features**: Supports wildcard SANs

### PKINIT KDC Profile (`pkinit_kdc`)
- **Purpose**: PKINIT KDC certificates for Kerberos authentication
- **Key Usage**: Digital signature only
- **Extended Key Usage**: Client and server authentication
- **Certificate Policy**: `1.3.6.1.5.2.3.5` (PKINIT KDC OID)
- **Lifetime**: 3650 days (10 years)
- **Features**: Includes Kerberos principal in SAN

### PKINIT Client Profile (`pkinit_client`)
- **Purpose**: PKINIT client certificates for Kerberos authentication
- **Key Usage**: Digital signature only
- **Extended Key Usage**: Client authentication
- **Certificate Policy**: `1.3.6.1.5.2.3.5` (PKINIT OID)
- **Lifetime**: 365 days
- **Features**: Includes Kerberos principal in SAN

### CA Profile (`ca`)
- **Purpose**: Certificate Authority certificates
- **Key Usage**: Digital signature, key cert sign, CRL sign
- **Basic Constraints**: CA=true
- **Lifetime**: 7300 days (20 years)

## Using Profiles

### In Certificate Requests

When requesting a certificate, specify the profile using the `profile` field:

```json
{
  "common_name": "user@EXAMPLE.COM",
  "organization": "Example Corp",
  "lifetime": 365,
  "profile": "pkinit_client",
  "force_issue": true
}
```

### In Lambda Invocations

When invoking the TLS certificate Lambda directly:

```python
request_payload = {
    "common_name": "krbtgt/EXAMPLE.COM@EXAMPLE.COM",
    "lifetime": 3650,
    "profile": "pkinit_kdc",
    "force_issue": True,
    "cert_bundle": True
}
```

## Custom Profiles

You can define custom profiles in your Terraform configuration:

```hcl
module "certificate_authority" {
  source = "serverless-ca/ca/aws"
  
  certificate_profiles = {
    "custom_server" = {
      description = "Custom server certificate with specific requirements"
      key_usage = {
        digital_signature = true
        key_encipherment  = true
        data_encipherment = false
        key_agreement     = false
        key_cert_sign     = false
        crl_sign          = false
        content_commitment = false
        encipher_only     = false
        decipher_only     = false
      }
      extended_key_usage = ["server_auth", "client_auth"]
      certificate_policies = ["2.23.140.1.2.1"]
      lifetime_days = 365
      max_lifetime_days = 365
      allow_wildcard_sans = true
    }
    
    "code_signing" = {
      description = "Code signing certificate"
      key_usage = {
        digital_signature = true
        content_commitment = true
        key_encipherment  = false
        data_encipherment = false
        key_agreement     = false
        key_cert_sign     = false
        crl_sign          = false
        encipher_only     = false
        decipher_only     = false
      }
      extended_key_usage = ["code_signing"]
      certificate_policies = ["1.3.6.1.5.5.7.2.3"]  # Code Signing OID
      lifetime_days = 1095  # 3 years
      max_lifetime_days = 1095
    }
  }
}
```

## Profile Configuration Options

### Key Usage
Controls the basic key usage extensions:
```hcl
key_usage = {
  digital_signature = true    # Digital signature
  key_encipherment  = true    # Key encipherment
  data_encipherment = false   # Data encipherment
  key_agreement     = false   # Key agreement
  key_cert_sign     = false   # Certificate signing
  crl_sign          = false   # CRL signing
  content_commitment = false  # Content commitment
  encipher_only     = false   # Encipher only
  decipher_only     = false   # Decipher only
}
```

### Extended Key Usage
List of extended key usage OIDs:
```hcl
extended_key_usage = [
  "client_auth",      # Client authentication
  "server_auth",      # Server authentication
  "code_signing",     # Code signing
  "email_protection", # Email protection
  "time_stamping",    # Time stamping
  "ocsp_signing"      # OCSP signing
]
```

### Basic Constraints
For CA certificates:
```hcl
basic_constraints = {
  ca = true           # Is a CA certificate
  path_length = null  # Path length constraint (null = unlimited)
}
```

### Certificate Policies
List of certificate policy OIDs:
```hcl
certificate_policies = [
  "2.23.140.1.2.1",  # DV Certificate Policy
  "1.3.6.1.5.2.3.5"  # PKINIT OID
]
```

### CRL Distribution Points
URLs for CRL distribution:
```hcl
crl_distribution_points = [
  "http://{domain}/issuing-ca.crl"
]
```

### Authority Information Access
URLs for CA certificate and OCSP:
```hcl
authority_info_access = [
  {
    access_method = "ca_issuers"
    url = "http://{domain}/issuing-ca.crt"
  },
  {
    access_method = "ocsp"
    url = "http://{domain}/ocsp"
  }
]
```

### Subject Alternative Names
Default SANs to include:
```hcl
subject_alt_names = [
  "DNS:example.com",
  "DNS:*.example.com",
  "IP:192.168.1.1"
]
```

### Lifetime Configuration
```hcl
lifetime_days = 365      # Default lifetime
max_lifetime_days = 365  # Maximum allowed lifetime
```

### Validation Options
```hcl
require_common_name = true   # Require common name
allow_wildcard_sans = false  # Allow wildcard SANs
```

## PKINIT Integration

The serverless CA provides built-in support for PKINIT certificates following the [FreeIPA PKINIT specification](https://www.freeipa.org/page/V4/Kerberos_PKINIT):

### KDC Certificates
- Common name format: `krbtgt/REALM@REALM`
- Includes Kerberos principal in Subject Alternative Name
- Uses PKINIT KDC OID (`1.3.6.1.5.2.3.5`)
- Long lifetime (10 years) for stability

### Client Certificates
- Common name format: `user@REALM` or `service@REALM`
- Includes Kerberos principal in Subject Alternative Name
- Uses PKINIT OID (`1.3.6.1.5.2.3.5`)
- Standard lifetime (1 year)

### Example Usage
```bash
# Generate PKINIT KDC certificate
python utils/pkinit-cert.py --type kdc --principal "krbtgt/EXAMPLE.COM@EXAMPLE.COM"

# Generate PKINIT client certificate
python utils/pkinit-cert.py --type client --principal "user@EXAMPLE.COM"
```

## Best Practices

1. **Use Appropriate Profiles**: Choose profiles that match your use case
2. **Set Correct Lifetimes**: KDC certificates can have longer lifetimes than client certificates
3. **Include Required Extensions**: Ensure all necessary extensions are included for your application
4. **Validate Certificate Policies**: Use the correct OIDs for your certificate type
5. **Test Integration**: Verify that issued certificates work with your target applications

## Troubleshooting

### Profile Not Found
- Ensure the profile name is spelled correctly
- Check that the profile is defined in your Terraform configuration
- Verify that the profile is loaded in the Lambda environment

### Invalid Extensions
- Review the profile configuration for syntax errors
- Ensure all required fields are provided
- Check that OIDs are in the correct format

### Certificate Validation Issues
- Verify that the certificate includes all required extensions
- Check that the certificate policy OIDs are correct
- Ensure the key usage matches your application requirements
