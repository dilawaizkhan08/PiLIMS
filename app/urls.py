from django.urls import include, path
from rest_framework import routers
from rest_framework.authtoken.views import obtain_auth_token
# from rest_framework_nested.routers import NestedDefaultRouter

from app import views

from app import file_utility
router = routers.DefaultRouter()

router.register(r'users', views.UserViewSet, basename='user')


urlpatterns = [
    path('', include(router.urls)),
    
    path("profile/", views.UserProfileUpdateView.as_view(), name="user-profile"),
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),
    path('verify-otp/', views.VerifyOTPView.as_view(), name='verify-otp'),
    path("login/", views.LoginView.as_view(), name="login"), 
    path('register/', views.RegisterView.as_view(), name='register'),
    
]
