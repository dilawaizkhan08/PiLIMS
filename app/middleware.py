from app.signals import set_current_user

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

