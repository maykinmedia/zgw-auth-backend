from drf_spectacular.extensions import OpenApiAuthenticationExtension


class ZGWAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "zgw_auth_backend.authentication.ZGWAuthentication"
    name = "ZGWAuthentication"

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "in": "beader",
            "bearerFormat": "JWT",
        }
