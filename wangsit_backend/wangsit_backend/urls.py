from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from authentication.api_auth import api
from authentication import views as auth_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', api.urls),
    path('social/', include('social_django.urls', namespace='social')),
    path('profile-test/', auth_views.profile_test, name='profile-test'),
    path('', RedirectView.as_view(url='/api-docs/', permanent=False)),
]
