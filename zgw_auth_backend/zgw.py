import logging
from typing import Any, Dict, Optional

from django.utils.translation import gettext_lazy as _

import jwt
from rest_framework import exceptions

from .models import ApplicationCredentials

logger = logging.getLogger(__name__)


ALG = "HS256"


class ZGWAuth:
    def __init__(self, encoded: str):
        self.encoded = encoded

    def __repr__(self):
        return "<%s %r>" % (self.__class__.__name__, self.payload)

    @property
    def payload(self) -> Optional[Dict[str, Any]]:
        if self.encoded is None:
            return None

        if not hasattr(self, "_payload"):
            # decode the JWT and validate it

            # jwt check
            try:
                payload = jwt.decode(self.encoded, verify=False)
            except jwt.DecodeError:
                logger.info("Invalid JWT encountered")
                raise exceptions.AuthenticationFailed(
                    _(
                        "JWT could not be decoded. Possibly you made a copy-paste mistake."
                    ),
                    code="jwt-decode-error",
                )

            # get client_id
            try:
                client_id = payload["client_id"]
            except KeyError:
                raise exceptions.AuthenticationFailed(
                    _("`client_id` claim is missing in the JWT."),
                    code="missing-client-identifier",
                )

            # find client_id in DB and retrieve its secret
            try:
                jwt_secret = ApplicationCredentials.objects.exclude(secret="").get(
                    client_id=client_id
                )
            except ApplicationCredentials.DoesNotExist:
                raise exceptions.AuthenticationFailed(
                    _("Client identifier does not exist"),
                    code="invalid-client-identifier",
                )
            else:
                key = jwt_secret.secret

            # check signature of the token
            try:
                payload = jwt.decode(self.encoded, key, algorithms=ALG)
            except jwt.InvalidSignatureError:
                logger.exception("Invalid signature - possible payload tampering?")
                raise exceptions.AuthenticationFailed(
                    _("Client credentials are invalid."), code="invalid-jwt-signature"
                )

            self._payload = payload

        return self._payload
