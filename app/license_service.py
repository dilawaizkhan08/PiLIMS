import json
import base64
import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from django.conf import settings
from pathlib import Path


LICENSE_PATH = Path(settings.BASE_DIR) / "license.lic"
PUBLIC_KEY = Path(settings.BASE_DIR) / "app/public_key.pem"


class LicenseError(Exception):
    pass


def validate_license():
    if not LICENSE_PATH.exists():
        raise LicenseError("License file missing")

    if not PUBLIC_KEY.exists():
        raise LicenseError("Public key missing")

    try:
        content = json.loads(LICENSE_PATH.read_text())

        data = base64.b64decode(content["data"])
        signature = base64.b64decode(content["signature"])

        with open(PUBLIC_KEY, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read()
            )

        # Verify RSA signature
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        lic = json.loads(data)

    except (KeyError, ValueError, json.JSONDecodeError) as e:
        raise LicenseError("Invalid license file") from e

    # Required license fields
    required_fields = [
        "license_id",
        "client_id",
        "max_users",
        "concurrent_users",
        "start_date",
        "end_date",
    ]

    for field in required_fields:
        if field not in lic:
            raise LicenseError(
                f"Invalid license: missing {field}"
            )

    # Validate user limits
    try:
        max_users = int(lic["max_users"])
        concurrent_users = int(lic["concurrent_users"])
    except (TypeError, ValueError) as e:
        raise LicenseError(
            "Invalid user limits in license"
        ) from e

    if max_users < 1:
        raise LicenseError(
            "Invalid license: max_users must be greater than 0"
        )

    if concurrent_users < 1:
        raise LicenseError(
            "Invalid license: concurrent_users must be greater than 0"
        )

    if concurrent_users > max_users:
        raise LicenseError(
            "Invalid license: concurrent_users cannot exceed max_users"
        )

    # Validate license dates
    try:
        start = datetime.date.fromisoformat(lic["start_date"])
        end = datetime.date.fromisoformat(lic["end_date"])
    except (TypeError, ValueError) as e:
        raise LicenseError(
            "Invalid license dates"
        ) from e

    if start > end:
        raise LicenseError(
            "Invalid license: start_date cannot be after end_date"
        )

    today = datetime.date.today()

    if today < start:
        raise LicenseError("License not active yet")

    if today > end:
        raise LicenseError("License expired")

    # Normalize values
    lic["max_users"] = max_users
    lic["concurrent_users"] = concurrent_users

    return lic