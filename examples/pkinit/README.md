# PKINIT Certificate Example

This example demonstrates how to use the serverless CA with PKINIT certificate profiles for Kerberos authentication.

## Overview

PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) allows Kerberos authentication using X.509 certificates instead of passwords. This example shows how to configure the serverless CA to issue PKINIT-compatible certificates.

## Features

- **PKINIT KDC Certificates**: Certificates for Kerberos Key Distribution Centers
- **PKINIT Client Certificates**: Certificates for Kerberos clients
- **Enhanced TLS Server Certificates**: Additional server certificate profiles
- **Custom Certificate Policies**: PKINIT-specific OIDs and extensions

## Certificate Profiles

### PKINIT KDC Profile (`pkinit_kdc`)
- **Purpose**: Certificates for Kerberos KDC servers
- **Key Usage**: Digital signature only (no key encipherment)
- **Extended Key Usage**: Client and server authentication
- **Certificate Policy**: `1.3.6.1.5.2.3.5` (PKINIT KDC OID)
- **Lifetime**: 10 years (3650 days)
- **Common Name**: Must be in format `krbtgt/REALM@REALM`

### PKINIT Client Profile (`pkinit_client`)
- **Purpose**: Certificates for Kerberos clients
- **Key Usage**: Digital signature only
- **Extended Key Usage**: Client authentication
- **Certificate Policy**: `1.3.6.1.5.2.3.5` (PKINIT OID)
- **Lifetime**: 1 year (365 days)
- **Common Name**: Should be in format `user@REALM` or `service@REALM`

## Usage

1. **Deploy the CA with PKINIT profiles**:
   ```bash
   terraform init
   terraform apply
   ```

2. **Start the CA**:
   - Execute the Step Function in AWS Console
   - Or wait for the scheduled run

3. **Issue PKINIT certificates**:
   - The example includes JSON files for KDC and client certificates
   - Certificates will be issued automatically via the Step Function

## Certificate Examples

### KDC Certificate
```json
{
  "common_name": "krbtgt/EXAMPLE.COM@EXAMPLE.COM",
  "organization": "Example Corp",
  "organizational_unit": "IT Department",
  "country": "US",
  "state": "California",
  "locality": "San Francisco",
  "lifetime": 3650,
  "profile": "pkinit_kdc",
  "force_issue": true
}
```

### Client Certificate
```json
{
  "common_name": "user@EXAMPLE.COM",
  "organization": "Example Corp",
  "organizational_unit": "IT Department",
  "country": "US",
  "state": "California",
  "locality": "San Francisco",
  "lifetime": 365,
  "profile": "pkinit_client",
  "force_issue": true
}
```

## Integration with FreeIPA

This implementation follows the [FreeIPA PKINIT specification](https://www.freeipa.org/page/V4/Kerberos_PKINIT) and provides:

- **KDC Certificates**: Compatible with FreeIPA KDC configuration
- **Client Certificates**: Support for user and service principal authentication
- **Certificate Policies**: Proper OIDs for PKINIT validation
- **Subject Alternative Names**: Kerberos principal names in SAN extensions

## Customization

You can customize the certificate profiles by modifying the `certificate_profiles` variable in `ca.tf`:

```hcl
certificate_profiles = {
  "custom_pkinit" = {
    description = "Custom PKINIT profile"
    key_usage = {
      digital_signature = true
      # ... other key usage settings
    }
    extended_key_usage = ["client_auth"]
    certificate_policies = ["1.3.6.1.5.2.3.5"]
    lifetime_days = 365
    # ... other settings
  }
}
```

## Security Considerations

- **Key Usage**: PKINIT certificates should only allow digital signature, not key encipherment
- **Certificate Policies**: Use the correct PKINIT OID (`1.3.6.1.5.2.3.5`)
- **Lifetime**: KDC certificates can have longer lifetimes than client certificates
- **Principal Names**: Ensure common names follow Kerberos principal naming conventions

## Troubleshooting

1. **Profile not found**: Ensure the profile name matches exactly in the certificate request
2. **Invalid extensions**: Check that the profile configuration includes required PKINIT extensions
3. **Certificate validation**: Verify that the issued certificates include the correct OIDs and extensions
