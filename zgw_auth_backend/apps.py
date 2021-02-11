from django.apps import AppConfig, apps


class ZgwAuthBackendConfig(AppConfig):
    name = "zgw_auth_backend"

    def ready(self):
        register_spectacular_extensions()


def register_spectacular_extensions():
    if not apps.is_installed("drf_spectacular"):
        return

    from .contrib import drf_spectacular  # noqa
