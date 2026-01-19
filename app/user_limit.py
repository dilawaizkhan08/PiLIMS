# app/user_limit.py
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()

def check_user_limit():
    max_users = settings.LICENSE_DATA.get("max_users", 1)  # default 1
    active = User.objects.filter(is_active=True).count()
    if active >= max_users:
        # Instead of raising generic exception, raise DRF-friendly
        from rest_framework.exceptions import ValidationError
        raise ValidationError("User limit reached for this license.")
