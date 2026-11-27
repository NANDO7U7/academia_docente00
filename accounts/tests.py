import re
from concurrent.futures import ThreadPoolExecutor
from secrets import token_urlsafe
from threading import Barrier

from django.contrib.auth import get_user_model
from django.core.exceptions import NON_FIELD_ERRORS
from django.db import connection
from django.db.models.signals import pre_save
from django.test import Client, TestCase, TransactionTestCase
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
            "email": "  DOCENTE.NUEVO+CURSO@EXAMPLE.COM  ",
            "password1": self.clave,
            "password2": self.clave,
        }
        sin_token = self.client.post(reverse("accounts:registro"), datos)
        self.assertEqual(sin_token.status_code, 403)

        respuesta = self.enviar_formulario("accounts:registro", datos)

        self.assertRedirects(respuesta, "/iniciar-sesion/")
        usuario = get_user_model().objects.get(username=datos["username"])
        self.assertEqual(usuario.email, "docente.nuevo+curso@example.com")
        self.assertTrue(usuario.check_password(self.clave))
        self.assertFalse(respuesta.wsgi_request.user.is_authenticated)

    def test_registro_con_correo_existente_conserva_la_cuenta(self):
        modelo = get_user_model()
        correo = "docente.prueba+curso@example.com"
        original = modelo.objects.create_user(
            username="docente_original", email=correo, password=self.clave
        )
        hash_original = original.password
        clave_nueva = token_urlsafe(24)
        for variante in (correo, correo.upper(), f"  {correo}  "):
            with self.subTest(correo=variante):
                respuesta = self.enviar_formulario(
                    "accounts:registro",
                    {
                        "username": "docente_repetido",
                        "email": variante,
                        "password1": clave_nueva,
                        "password2": clave_nueva,
                    },
                )
                self.assertRedirects(
                    respuesta, "/iniciar-sesion/", fetch_redirect_response=False
                )
                self.assertEqual(respuesta.content, b"")
                self.assertFalse(modelo.objects.filter(username="docente_repetido").exists())

        original.refresh_from_db()
        self.assertEqual(original.password, hash_original)
        self.assertTrue(original.check_password(self.clave))

    def test_registro_con_claves_distintas_no_crea_cuenta(self):
        correo = "docente.no-creado@example.com"
        respuesta = self.enviar_formulario(
            "accounts:registro",
            {
                "username": "docente_no_creado",
                "email": correo,
                "password1": self.clave,
                "password2": self.clave + "!",
            },
        )

        self.assertEqual(respuesta.status_code, 200)
        self.assertTrue(respuesta.context["form"].has_error("password2"))
        self.assertContains(respuesta, f'value="{correo}"')
        self.assertFalse(
            get_user_model().objects.filter(username="docente_no_creado").exists()
        )

    def test_registro_rechaza_correo_invalido_vacio_u_omitido(self):
        datos = {
            "username": "docente_sin_correo_valido",
            "password1": self.clave,
            "password2": self.clave,
        }
        correo_largo = f"{'a' * 60}@{'b' * 63}.{'c' * 63}.{'d' * 63}.example"
        casos = (
            ("correo-invalido", "invalid"),
            ("", "required"),
            (None, "required"),
            ("   ", "required"),
            (correo_largo, "max_length"),
        )
        for correo, codigo in casos:
            with self.subTest(correo=correo):
                datos_correo = {} if correo is None else {"email": correo}
                respuesta = self.enviar_formulario(
                    "accounts:registro", {**datos, **datos_correo}
                )

                self.assertContains(respuesta, 'class="errorlist" id="id_email_error"')
                self.assertContains(respuesta, f'value="{correo or ""}"')
                errores = respuesta.context["email_errors"].as_data()
                self.assertEqual([error.code for error in errores], [codigo])
                self.assertFalse(
                    get_user_model().objects.filter(username=datos["username"]).exists()
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


class RegistroConcurrenteTests(TransactionTestCase):
    def test_nombre_duplicado_en_altas_simultaneas(self):
        modelo = get_user_model()
        nombre = "docente_simultaneo"
        url = reverse("accounts:registro")
        barrera = Barrier(2, timeout=10)
        solicitudes = []
        for correo in ("  PRIMERO@EXAMPLE.TEST  ", "  SEGUNDO@EXAMPLE.TEST  "):
            clave = token_urlsafe(24)
            solicitudes.append(
                {
                    "username": nombre,
                    "email": correo,
                    "password1": clave,
                    "password2": clave,
                }
            )

        def sincronizar_guardados(sender, instance, **kwargs):
            if instance.username == nombre and instance._state.adding:
                barrera.wait()

        def enviar_registro(datos):
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    pid = cursor.fetchone()[0]
                respuesta = Client(raise_request_exception=False).post(url, datos)
                return pid, datos, respuesta
            finally:
                connection.close()

        pre_save.connect(sincronizar_guardados, sender=modelo)
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                resultados = list(executor.map(enviar_registro, solicitudes))
        finally:
            pre_save.disconnect(sincronizar_guardados, sender=modelo)

        self.assertEqual(len({pid for pid, _, _ in resultados}), 2)
        self.assertEqual(
            sorted(respuesta.status_code for _, _, respuesta in resultados), [200, 302]
        )
        por_estado = {
            respuesta.status_code: (datos, respuesta)
            for _, datos, respuesta in resultados
        }
        datos_ganadores, aceptada = por_estado[302]
        datos_rechazados, rechazada = por_estado[200]
        self.assertRedirects(aceptada, "/iniciar-sesion/", fetch_redirect_response=False)
        self.assertTemplateUsed(rechazada, "accounts/registro.html")
        self.assertTrue(rechazada.context["form"].has_error("username", "unique"))
        self.assertContains(rechazada, "Ya existe un usuario con este nombre.")
        self.assertContains(rechazada, f'value="{datos_rechazados["email"]}"')

        self.assertEqual(modelo.objects.count(), 1)
        guardada = modelo.objects.get(username=nombre)
        self.assertEqual(guardada.email, datos_ganadores["email"].strip().lower())
        self.assertTrue(guardada.check_password(datos_ganadores["password1"]))
        self.assertFalse(guardada.check_password(datos_rechazados["password1"]))
