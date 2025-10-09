from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authtoken.models import Token
from django.utils import timezone
from datetime import timedelta
from app.models import SystemConfiguration

class IdleTimeoutTokenAuthentication(TokenAuthentication):
    """
    Extends DRF TokenAuthentication with idle timeout logic.
    No DB model changes required.
    """

    def authenticate_credentials(self, key):
        try:
            token = Token.objects.select_related('user').get(key=key)
        except Token.DoesNotExist:
            raise AuthenticationFailed('Invalid token.')

        if not token.user.is_active:
            raise AuthenticationFailed('User inactive or deleted.')

        # Get timeout from SystemConfiguration
        timeout_minutes = 30
        config = SystemConfiguration.objects.filter(key="user_idle_time_minutes").first()
        if config and config.value.isdigit():
            timeout_minutes = int(config.value)

        # Fetch last activity time from session
        last_activity = token.user.last_login  # can use a separate field if needed
        now = timezone.now()

        # If no activity, fallback to token creation time
        last_time = last_activity or token.created
        if now - last_time > timedelta(minutes=timeout_minutes):
            token.delete()
            raise AuthenticationFailed('Session expired due to inactivity. Please log in again.')

        # Update last login time (i.e., activity)
        token.user.last_login = now
        token.user.save(update_fields=["last_login"])

        return (token.user, token)
