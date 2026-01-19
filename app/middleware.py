from app.signals import set_current_user
from django.conf import settings
from django.http import JsonResponse

class CurrentUserMiddleware:
    """Stores the currently logged-in user for signals to use."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            print(f"✅ Middleware set_current_user: {user}")
            set_current_user(user)
        response = self.get_response(request)
        return response
    



class LicenseMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not getattr(settings, "LICENSE_VALID", False):
            return JsonResponse({
                "error": "License invalid or expired"
            }, status=403)
        return self.get_response(request)


