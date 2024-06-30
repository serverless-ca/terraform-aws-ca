import os
import json


class Config:
    def __init__(self):
        self.domain = None
        self.environment_name = None
        self.external_s3_bucket = None
        self.internal_s3_bucket = None
        self.project = None
        self.public_crl = None
        self.root_ca_info = None
        self.issuing_ca_info = None
        self.max_cert_lifetime = None

    def is_production_environment(self):
        if self.environment_name in ["prd", "prod"]:
            return True
        return False

    def enable_public_crl(self):
        return self.public_crl == "enabled"

    @staticmethod
    def from_env():
        return Config.from_dict(os.environ)

    @staticmethod
    def from_dict(env_dict):
        cfg = Config()

        cfg.max_cert_lifetime = int(env_dict["MAX_CERT_LIFETIME"])
        cfg.issuing_ca_info = json.loads(env_dict["ISSUING_CA_INFO"])
        cfg.root_ca_info = json.loads(env_dict["ROOT_CA_INFO"])
        cfg.domain = env_dict.get("DOMAIN")
        cfg.environment_name = env_dict["ENVIRONMENT_NAME"]
        cfg.external_s3_bucket = env_dict["EXTERNAL_S3_BUCKET"]
        cfg.internal_s3_bucket = env_dict["INTERNAL_S3_BUCKET"]
        cfg.project = env_dict["PROJECT"]
        cfg.public_crl = env_dict["PUBLIC_CRL"]

        return cfg
