import re
from secrets import token_urlsafe

from django.contrib.auth import get_user_model
from django.core.exceptions import NON_FIELD_ERRORS
from django.test import Client, TestCase
from django.urls import reverse


class FlujoDeCuentasTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.clave = token_urlsafe(24)
        cls.usuario = get_user_model().objects.create_user(
            username="docente_pruebas", password=cls.clave
        )

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)

    def enviar_formulario(self, pagina, datos, *, destino=None):
        respuesta = self.client.get(reverse(pagina))
        self.assertEqual(respuesta.status_code, 200)
        token = re.search(
            rb'name="csrfmiddlewaretoken" value="([^"]+)"', respuesta.content
        )
        self.assertIsNotNone(token, "El formulario debe incluir un token CSRF.")
        return self.client.post(
            reverse(destino or pagina),
            {**datos, "csrfmiddlewaretoken": token.group(1).decode("ascii")},
        )

    def test_registro_valido(self):
        datos = {
            "username": "docente_nuevo",
            "password1": self.clave,
            "password2": self.clave,
        }
        sin_token = self.client.post(reverse("accounts:registro"), datos)
        self.assertEqual(sin_token.status_code, 403)

        respuesta = self.enviar_formulario("accounts:registro", datos)

        self.assertRedirects(respuesta, "/iniciar-sesion/")
        usuario = get_user_model().objects.get(username=datos["username"])
        self.assertTrue(usuario.check_password(self.clave))
        self.assertFalse(respuesta.wsgi_request.user.is_authenticated)

    def test_registro_con_claves_distintas_no_crea_cuenta(self):
        respuesta = self.enviar_formulario(
            "accounts:registro",
            {
                "username": "docente_no_creado",
                "password1": self.clave,
                "password2": self.clave + "!",
            },
        )

        self.assertEqual(respuesta.status_code, 200)
        self.assertTrue(respuesta.context["form"].has_error("password2"))
        self.assertFalse(
            get_user_model().objects.filter(username="docente_no_creado").exists()
        )

    def test_visita_anonima_al_panel(self):
        respuesta = self.client.get("/panel/")

        self.assertRedirects(respuesta, "/iniciar-sesion/?next=/panel/")

    def test_inicio_de_sesion_con_usuario_inexistente(self):
        respuesta = self.enviar_formulario(
            "accounts:login",
            {"username": "docente_inexistente", "password": self.clave},
        )

        self.assertEqual(respuesta.status_code, 200)
        self.assertTrue(
            respuesta.context["form"].has_error(NON_FIELD_ERRORS, "invalid_login")
        )
        self.assertFalse(respuesta.wsgi_request.user.is_authenticated)

    def test_inicio_de_sesion_con_clave_incorrecta(self):
        respuesta = self.enviar_formulario(
            "accounts:login",
            {"username": self.usuario.username, "password": self.clave + "!"},
        )

        self.assertEqual(respuesta.status_code, 200)
        self.assertTrue(
            respuesta.context["form"].has_error(NON_FIELD_ERRORS, "invalid_login")
        )
        self.assertFalse(respuesta.wsgi_request.user.is_authenticated)

    def test_inicio_de_sesion_valido_muestra_el_usuario_en_el_panel(self):
        datos = {"username": self.usuario.username, "password": self.clave}
        sin_token = self.client.post(reverse("accounts:login"), datos)
        self.assertEqual(sin_token.status_code, 403)

        respuesta = self.enviar_formulario("accounts:login", datos)

        self.assertRedirects(respuesta, "/panel/", fetch_redirect_response=False)
        panel = self.client.get("/panel/")
        self.assertEqual(panel.status_code, 200)
        self.assertEqual(panel.wsgi_request.user.pk, self.usuario.pk)
        self.assertTrue(self.usuario.username.encode() in panel.content)

    def test_cierre_de_sesion_protege_la_siguiente_visita_al_panel(self):
        self.client.force_login(self.usuario)
        url_cierre = reverse("accounts:logout")
        self.assertEqual(self.client.get(url_cierre).status_code, 405)
        self.assertEqual(self.client.post(url_cierre).status_code, 403)

        respuesta = self.enviar_formulario(
            "accounts:panel", {}, destino="accounts:logout"
        )

        self.assertRedirects(respuesta, "/iniciar-sesion/")
        self.assertRedirects(
            self.client.get("/panel/"), "/iniciar-sesion/?next=/panel/"
        )
