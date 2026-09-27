from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from rest_framework.authtoken.models import Token


User = get_user_model()


def check_user_limit():
    license_data = settings.LICENSE_DATA or {}

    max_users = int(
        license_data.get("max_users", 1)
    )

    active_users = User.objects.filter(
        is_active=True
    ).count()

    if active_users >= max_users:
        raise ValidationError(
            "User limit reached for this license."
        )


def check_concurrent_user_limit(user):
    license_data = settings.LICENSE_DATA or {}

    concurrent_limit = int(
        license_data.get("concurrent_users", 1)
    )

    # Debug
    print("\n========== CONCURRENT USER CHECK ==========")
    print("License concurrent_users:", concurrent_limit)
    print("Login user:", user.email)

    # Current user already has a token
    existing_token = Token.objects.filter(
        user=user
    ).exists()

    print("Current user has token:", existing_token)

    if existing_token:
        print("RESULT: ALLOWED - user already logged in")
        print("===========================================\n")
        return

    # Count currently active token users
    concurrent_users = Token.objects.filter(
        user__is_active=True
    ).count()

    print("Current token users:", concurrent_users)

    if concurrent_users >= concurrent_limit:
        print("RESULT: BLOCKED - concurrent limit reached")
        print("===========================================\n")

        raise ValidationError(
            "Concurrent user limit reached for this license."
        )

    print("RESULT: ALLOWED - slot available")
    print("===========================================\n")