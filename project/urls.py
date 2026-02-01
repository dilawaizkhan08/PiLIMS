from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views  # import this
from django.http import Http404
from django.urls import include, path
from django.views.generic.base import RedirectView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView


def View404(request, *args, **kwargs):
    raise Http404("Page not found")


urlpatterns = [
    
    path("admin/", admin.site.urls),
    path("api/", include("app.urls")),
    # path("events/", include("django_eventstream.urls")),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += [
    path("<path:unknown_path>", View404),
]