# authentication.py

from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authtoken.models import Token
from django.utils import timezone
from datetime import timedelta
from app.models import SystemConfiguration, User
from django.contrib.auth.backends import ModelBackend


class IdleTimeoutTokenAuthentication(TokenAuthentication):
    """
    TokenAuthentication with idle timeout using `last_activity`.
    """

    def authenticate_credentials(self, key):
        try:
            token = Token.objects.select_related("user").get(key=key)
        except Token.DoesNotExist:
            raise AuthenticationFailed("Invalid token.")

        user = token.user

        if not user.is_active:
            raise AuthenticationFailed("User inactive or deleted.")

        # Get idle timeout from system configuration
        timeout_minutes = 30  # default
        config = SystemConfiguration.objects.filter(key="user_idle_time_minutes").first()
        if config and config.value.isdigit():
            timeout_minutes = int(config.value)

        now = timezone.now()
        last_activity = user.last_activity or token.created

        # Safety: if last_activity somehow in the future, reset to now
        if last_activity > now:
            last_activity = now

        if now - last_activity > timedelta(minutes=timeout_minutes):
            # Expire token
            token.delete()
            raise AuthenticationFailed(
                "Session expired due to inactivity. Please log in again."
            )

        # Update last_activity timestamp
        user.last_activity = now
        user.save(update_fields=["last_activity"])

        return (user, token)


class EmailBackend(ModelBackend):
    """
    Custom authentication backend using email instead of username.
    """

    def authenticate(self, request, email=None, password=None, **kwargs):
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
