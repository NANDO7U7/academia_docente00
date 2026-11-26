from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy

from . import views

app_name = "accounts"

urlpatterns = [
    path("registro/", views.registro, name="registro"),
    path(
        "iniciar-sesion/",
        auth_views.LoginView.as_view(
            template_name="accounts/login.html",
            next_page=reverse_lazy("accounts:panel"),
        ),
        name="login",
    ),
    path("panel/", views.panel, name="panel"),
    path(
        "cerrar-sesion/",
        auth_views.LogoutView.as_view(next_page=reverse_lazy("accounts:login")),
        name="logout",
    ),
]
