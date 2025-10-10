from .signals import set_current_user

class CurrentUserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # request.user is available here after AuthenticationMiddleware
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            set_current_user(user)
            print(f"[Middleware] Authenticated: True, User: {user}")
        else:
            set_current_user(None)
            print(f"[Middleware] Authenticated: False, User: None")

        response = self.get_response(request)

        # Clear after response to avoid user leakage between requests
        set_current_user(None)

        return response
