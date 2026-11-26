from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods


@sensitive_post_parameters("password1", "password2")
@require_http_methods(["GET", "POST"])
def registro(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("accounts:login")
    else:
        form = UserCreationForm()

    return render(request, "accounts/registro.html", {"form": form})


@login_required(login_url="accounts:login")
@never_cache
def panel(request):
    return render(request, "accounts/panel.html")
