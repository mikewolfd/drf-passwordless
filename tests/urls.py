from django.urls import include, re_path
from django.urls import path, include
from rest_framework.urlpatterns import format_suffix_patterns
urlpatterns = (
    path(r"passwordless/", include("jwt_drf_passwordless.urls")),
)

app_name = 'jwt_drf_passwordless'

format_suffix_patterns(urlpatterns)