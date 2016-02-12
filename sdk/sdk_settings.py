import os
from base64 import b64decode

# Link Server Settings
LINK_SERVER_URL = os.getenv("LINK_SERVER_URL", "https://link.example.com/v1/")

# Beaker Server Settings
BEAKER_SERVER_URL = os.getenv("BEAKER_SERVER_URL", "http://api.example.com/api/v1/service/")
BEAKER_API_USERNAME = os.getenv("BEAKER_API_USERNAME", "")
BEAKER_API_PASSWORD = os.getenv("BEAKER_API_PASSWORD", "")

# Redis Server Settings
REDIS_ENABLED = os.getenv("REDIS_ENABLED", False)
REDIS_SERVER_HOST = os.getenv("REDIS_SERVER_HOST", "redis.example.com")
REDIS_SERVER_PORT = int(os.getenv("REDIS_SERVER_PORT", 6379))
REDIS_SERVER_PASSWORD = os.getenv("REDIS_SERVER_PASSWORD", "changeme")
REDIS_SERVER_TIMEOUT = int(os.getenv("REDIS_SERVER_PORT", 4))

# Statsd Server Settings
STATSD_ENABLED = os.getenv("STATSD_ENABLED", False)
STATSD_SERVER_HOST = os.getenv("STATSD_SERVER_HOST", "")
STATSD_SERVER_PORT = os.getenv("STATSD_SERVER_PORT", 0)

# External SMTP System (for alerts, etc)
EXTERNAL_EMAIL_HOST = os.getenv("EXTERNAL_EMAIL_HOST", "smtp.example.com")
EXTERNAL_EMAIL_USERNAME = os.getenv("EXTERNAL_EMAIL_USERNAME", "changeme")
EXTERNAL_EMAIL_PASSWORD = os.getenv("EXTERNAL_EMAIL_PASSWORD", "changeme")

# API v1 Elliptic Curve Private Key (NIST256p) FOR TESTING / LOCAL DEV ONLY
API_V1_ECDSA_PRIVATE = """
MHcCAQEEIL3emamn8X5hyM7mISUi45XCUzNqelq2uqn5zjVmPai7oAoGCCqGSM49
AwEHoUQDQgAEYuT83RA8bhg9j9dYR8jCRW1rD7Jl2RSThivlsSn26/9pwDZV5nnb
sq0PEwmhpVJiB/eXpLMVtKrWKER8v+U9xw==
"""
API_V1_ECDSA_PRIVATE = os.getenv("API_V1_ECDSA_PRIVATE", API_V1_ECDSA_PRIVATE)

# API v1 Elliptic Curve Public Key (NIST256p) FOR TESTING / LOCAL DEV ONLY
API_V1_ECDSA_PUBLIC = """
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYuT83RA8bhg9j9dYR8jCRW1rD7Jl
2RSThivlsSn26/9pwDZV5nnbsq0PEwmhpVJiB/eXpLMVtKrWKER8v+U9xw==
"""
API_V1_ECDSA_PUBLIC = os.getenv("API_V1_ECDSA_PUBLIC", API_V1_ECDSA_PUBLIC)

try:
    from sdk_settingslocal import *
except ImportError:
    pass
