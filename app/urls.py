from django.urls import include, path
from rest_framework import routers
from rest_framework.authtoken.views import obtain_auth_token
# from rest_framework_nested.routers import NestedDefaultRouter

from app import views

from app import file_utility
router = routers.DefaultRouter()

router.register(r'users', views.UserViewSet, basename='user')
router.register(r'analyses', views.AnalysisViewSet, basename='analysis')
router.register(r'user-groups', views.UserGroupViewSet, basename='usergroup')
router.register(r'test-methods', views.TestMethodViewSet, basename='testmethod')
router.register(r'components', views.ComponentViewSet, basename='component')
router.register(r'functions', views.CustomFunctionViewSet, basename='functions')
router.register(r'instruments', views.InstrumentViewSet, basename='instrument')
router.register(r'instrument-history', views.InstrumentHistoryViewSet, basename='instrument-history')
router.register(r'inventory', views.InventoryViewSet, basename='inventory')
router.register(r'stock', views.StockViewSet, basename='stock')
router.register(r'units', views.UnitViewSet, basename='units')
router.register(r'customer', views.CustomerViewSet, basename='customer')
router.register(r'lists', views.ListViewSet, basename='lists')
router.register(r'values', views.ValueViewSet, basename='values')
router.register(r'sample-forms', views.SampleFormViewSet, basename='sample-forms')
router.register(r'request-forms', views.RequestFormViewSet, basename='requestform')
router.register(r'products', views.ProductViewSet, basename='products')

router.register(r'roles', views.RoleViewSet,  basename="roles")
router.register(r'modules', views.ModuleViewSet, basename="modules")



urlpatterns = [
    path('', include(router.urls)),
    
    path("profile/", views.UserProfileUpdateView.as_view(), name="user-profile"),
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),
    path('verify-otp/', views.VerifyOTPView.as_view(), name='verify-otp'),
    path("login/", views.LoginView.as_view(), name="login"), 
    path('register/', views.RegisterView.as_view(), name='register'),

    path('sample-forms/<int:form_id>/fields/', views.SampleFormSchemaView.as_view()),
    path('sample-forms/<int:form_id>/submit/', views.SampleFormSubmitView.as_view()),

    path('request-forms/<int:form_id>/schema/', views.RequestFormSchemaView.as_view(), name='request-form-schema'),
    path('request-forms/<int:form_id>/submit/', views.RequestFormSubmitView.as_view(), name='request-form-submit'),
    
]
