module "certificate_authority" {
  source = "../../"
  # source  = "serverless-ca/ca/aws"
  # version = "1.0.0"

  # Enable PKINIT certificate profiles
  certificate_profiles = {
    "pkinit_kdc" = {
      description = "PKINIT KDC certificate for Kerberos authentication"
      key_usage = {
        digital_signature = true
        key_encipherment  = false
        data_encipherment = false
        key_agreement     = false
        key_cert_sign     = false
        crl_sign          = false
        content_commitment = false
        encipher_only     = false
        decipher_only     = false
      }
      extended_key_usage = ["client_auth", "server_auth"]
      certificate_policies = ["1.3.6.1.5.2.3.5"]  # PKINIT KDC OID
      lifetime_days = 3650  # 10 years for KDC certificates
      max_lifetime_days = 3650
      require_common_name = true
    }
    
    "pkinit_client" = {
      description = "PKINIT client certificate for Kerberos authentication"
      key_usage = {
        digital_signature = true
        key_encipherment  = false
        data_encipherment = false
        key_agreement     = false
        key_cert_sign     = false
        crl_sign          = false
        content_commitment = false
        encipher_only     = false
        decipher_only     = false
      }
      extended_key_usage = ["client_auth"]
      certificate_policies = ["1.3.6.1.5.2.3.5"]  # PKINIT OID
      lifetime_days = 365
      max_lifetime_days = 365
      require_common_name = true
    }
    
    "tls_server_enhanced" = {
      description = "Enhanced TLS server certificate with additional extensions"
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
      certificate_policies = ["2.23.140.1.2.1"]  # DV Certificate Policy
      lifetime_days = 365
      max_lifetime_days = 365
      allow_wildcard_sans = true
    }
  }

  # Example certificate info files for PKINIT
  cert_info_files = ["pkinit-kdc", "pkinit-client"]

  providers = {
    aws           = aws
    aws.us-east-1 = aws.us-east-1 # required even if CloudFront not used
  }
}
