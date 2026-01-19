# app/apps.py
from django.apps import AppConfig
from django.conf import settings
from .license_service import validate_license, LicenseError

class AppConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "app"  # <-- sirf ek unique name

    def ready(self):
        # Load signals
        import app.signals

        # License validation
        try:
            settings.LICENSE_DATA = validate_license()
            settings.LICENSE_VALID = True
            settings.LICENSE_ERROR = None
        except LicenseError as e:
            settings.LICENSE_DATA = None
            settings.LICENSE_VALID = False
            settings.LICENSE_ERROR = str(e)
