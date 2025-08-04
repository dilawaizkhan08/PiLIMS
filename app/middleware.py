# app/middleware.py
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

# class DisableCSRFMiddleware(MiddlewareMixin):
#     def process_request(self, request):
#         try:
#             token_auth = TokenAuthentication()
#             user_auth_tuple = token_auth.authenticate(request)
#             if user_auth_tuple is not None:
#                 request.user, _ = user_auth_tuple
#                 setattr(request, '_dont_enforce_csrf_checks', True)
#         except AuthenticationFailed:
#             pass
