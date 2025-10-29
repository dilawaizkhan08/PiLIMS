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
router.register(r'attachments', views.AnalysisAttachmentViewSet, basename='attachments')
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
router.register(r"sample-entries", views.DynamicSampleFormEntryViewSet, basename='sample-entries')
router.register(r'request-forms', views.RequestFormViewSet, basename='requestform')
router.register(r"request-entries", views.DynamicRequestFormEntryViewSet, basename='request-entries')

router.register(r'products', views.ProductViewSet, basename='products')

router.register(r'roles', views.RoleViewSet,  basename="roles")
router.register(r'modules', views.ModuleViewSet, basename="modules")
router.register(r'request-attachments', views.DynamicRequestAttachmentViewSet, basename='request-attachments')
router.register(r'sample-attachments', views.DynamicFormAttachmentViewSet, basename='sample-attachments')
router.register(r'activities', views.ActivityViewSet, basename='activity')




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


    path("table-data/", views.DynamicTableDataView.as_view(), name="table-data"),

    path("entries/<int:entry_id>/analyses/", views.EntryAnalysesSchemaView.as_view(), name="entry-analyses-schema"),
    path("entries/<int:entry_id>/analysis/<int:analysis_id>/submit/", views.AnalysisResultSubmitView.as_view(), name="analysis-submit"),
     

    path("configs/", views.SystemConfigurationListCreateView.as_view(), name="config-list"),
    path("configs/<int:pk>/", views.SystemConfigurationDetailView.as_view(), name="config-detail"),
    path("configs/bulk-update/", views.BulkConfigUpdateView.as_view(), name="bulk-config-update"),
    path("dynamic-report/", views.MultiDynamicReportView.as_view(), name="dynamic-report"),
    path("dynamic-report-schema/", views.MultiDynamicReportSchemaView.as_view(), name="dynamic-report-schema"),

    path('generate-pdf/', views.HTMLToPDFView.as_view(), name='generate-pdf'),

    path("create-template/", views.ReportTemplateCreateView.as_view(), name="create_template"),
    path("render-report/", views.RenderReportView.as_view(), name="render_report"),

]
