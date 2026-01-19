import json, base64, datetime
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

    content = json.loads(LICENSE_PATH.read_text())

    data = base64.b64decode(content["data"])
    signature = base64.b64decode(content["signature"])

    with open(PUBLIC_KEY, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    public_key.verify(
        signature,
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    lic = json.loads(data)

    today = datetime.date.today()
    start = datetime.date.fromisoformat(lic["start_date"])
    end = datetime.date.fromisoformat(lic["end_date"])

    if today < start or today > end:
        raise LicenseError("License expired")

    return lic
