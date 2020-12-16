from django.db import models
from django.utils.translation import gettext_lazy as _


class ApplicationCredentials(models.Model):
    client_id = models.CharField(
        _("client ID"),
        max_length=50,
        unique=True,
        help_text=_(
            "Client ID to identify external API's and applications that access this API."
        ),
    )
    secret = models.CharField(
        _("secret"), max_length=255, help_text=_("Secret belonging to the client ID.")
    )

    class Meta:
        verbose_name = _("client credential")
        verbose_name_plural = _("client credentials")

    def __str__(self):
        return self.client_id
