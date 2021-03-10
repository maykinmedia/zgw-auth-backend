from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import path

from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.test import APITestCase
from rest_framework.views import APIView
from zds_client import ClientAuth

from zgw_auth_backend.authentication import ZGWAuthentication
from zgw_auth_backend.models import ApplicationCredentials

User = get_user_model()


class MockView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (ZGWAuthentication,)

    def get(self, request):
        return Response({"a": 1})


urlpatterns = [
    path("mock", MockView.as_view(), name="test"),
]


@override_settings(ROOT_URLCONF=__name__)
class ZGWAuthTests(APITestCase):
    def test_missing_header(self):
        response = self.client.get("/mock")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(User.objects.exists())

    def test_invalid_credentials(self):
        auth = ClientAuth(client_id="dummy", secret="secret")

        response = self.client.get(
            "/mock", HTTP_AUTHORIZATION=auth.credentials()["Authorization"]
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(User.objects.exists())

    def test_missing_claims(self):
        ApplicationCredentials.objects.create(client_id="dummy", secret="secret")
        auth = ClientAuth(client_id="dummy", secret="secret")

        response = self.client.get(
            "/mock", HTTP_AUTHORIZATION=auth.credentials()["Authorization"]
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(User.objects.exists())

    def test_valid_credentials(self):
        ApplicationCredentials.objects.create(client_id="dummy", secret="secret")
        auth = ClientAuth(
            client_id="dummy",
            secret="secret",
            user_id="some-user",
            user_representation="Some User",
            user_email="some@emailaddress.com",
        )

        response = self.client.get(
            "/mock", HTTP_AUTHORIZATION=auth.credentials()["Authorization"]
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(User.objects.count(), 1)
        user = User.objects.get()
        username = getattr(user, User.USERNAME_FIELD)
        self.assertEqual(username, "some-user")
        email = getattr(user, User.EMAIL_FIELD)
        self.assertEqual(email, "some@emailaddress.com")

    def test_no_duplicate_users(self):
        ApplicationCredentials.objects.create(client_id="dummy", secret="secret")
        User.objects.create(**{User.USERNAME_FIELD: "some-user"})
        auth = ClientAuth(
            client_id="dummy",
            secret="secret",
            user_id="some-user",
            user_representation="Some User",
        )

        response = self.client.get(
            "/mock", HTTP_AUTHORIZATION=auth.credentials()["Authorization"]
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(User.objects.count(), 1)
