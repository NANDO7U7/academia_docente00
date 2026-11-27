from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.forms.utils import ErrorList
from django.shortcuts import redirect, render
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods


@sensitive_post_parameters("password1", "password2")
@require_http_methods(["GET", "POST"])
def registro(request):
    email_errors = ErrorList(field_id="id_email")
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        email = request.POST.get("email", "").strip().lower()
        if not email:
            email_errors.append(
                ValidationError(_("This field is required."), code="required")
            )
        else:
            try:
                form.instance._meta.get_field("email").run_validators(email)
            except ValidationError as error:
                email_errors.extend(error.error_list)

        if form.is_valid() and not email_errors:
            form.instance.email = email
            try:
                with transaction.atomic():
                    form.save()
            except IntegrityError as error:
                violation = error.__cause__
                diagnostics = getattr(violation, "diag", None)
                if (
                    getattr(violation, "sqlstate", None) != "23505"
                    or getattr(diagnostics, "table_name", None) != "auth_user"
                ):
                    raise
                constraint_name = getattr(diagnostics, "constraint_name", None)
                if constraint_name == "auth_user_username_key":
                    form.add_error(
                        "username",
                        form.instance.unique_error_message(
                            form._meta.model, ["username"]
                        ),
                    )
                elif constraint_name != "auth_user_email_normalized_uniq":
                    raise
            if not form.errors:
                return redirect("accounts:login")
    else:
        form = UserCreationForm()

    return render(
        request, "accounts/registro.html", {"form": form, "email_errors": email_errors}
    )


@login_required(login_url="accounts:login")
@never_cache
def panel(request):
    return render(request, "accounts/panel.html")
