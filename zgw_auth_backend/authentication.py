# Mostly taken from https://github.com/VNG-Realisatie/vng-api-common/blob/master/vng_api_common/middleware.py
#
# We can't use vng-api-common at the moment because of the hard pinned dependencies on
# DRF 3.10 and drf-yasg 1.16.0
import logging

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.request import Request

from .zgw import ZGWAuth

logger = logging.getLogger(__name__)


class ZGWAuthentication(BaseAuthentication):
    www_authenticate_realm = "api"

    def authenticate(self, request: Request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b"bearer":
            return None

        if len(auth) == 1:
            msg = _("Invalid bearer header. No credentials provided.")
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _(
                "Invalid bearer header. Credentials string should not contain spaces."
            )
            raise exceptions.AuthenticationFailed(msg)

        auth = ZGWAuth(auth[1].decode("utf-8"))

        user_id = auth.payload.get("user_id")
        if not user_id:
            msg = _("Invalid 'user_id' claim. The 'user_id' should not be empty.")
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_user_id(user_id)

    def authenticate_user_id(self, username: str):
        UserModel = get_user_model()
        user, created = UserModel._default_manager.get_or_create(
            **{UserModel.USERNAME_FIELD: username}
        )
        if created:
            logger.info("Created user object for username %s", username)
        return (user, None)

    def authenticate_header(self, request):
        return 'Bearer realm="%s"' % self.www_authenticate_realm
