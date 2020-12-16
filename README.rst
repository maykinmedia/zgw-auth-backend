Welcome to zgw-auth-backend's documentation!
============================================

:Version: 1.0.1
:Source: https://github.com/maykinmedia/zgw-auth-backend
:Keywords: zgw, vng, apis, drf
:PythonVersion: 3.8

|build-status| |coverage| |linting| |black|

|python-versions| |django-versions| |pypi-version|

A Django REST framework authentication class for the ZGW API authentication pattern.

The ZGW Auth JWT includes claims for ``user_id`` and ``user_representation``. This
information can be used in your API to authenticate the actual end-user, even when
using gateway APIs.

.. contents::

.. section-numbering::

Features
========

* Authenticates the end-user based on the ``user_id`` JWT claim
* Follows the auth spec for "API's voor zaakgericht werken"

Installation
============

Requirements
------------

* Python 3.7 or higher
* setuptools 30.3.0 or above
* Django 2.2 or newer


Install
-------

.. code-block:: bash

    pip install zgw-auth-backend

Add it to your installed apps:

.. code-block:: py

    INSTALLED_APPS += ["zgw_auth_backend"]

Migrate:

.. code-block:: bash

    python manage.py migrate

Optionally, you can add it to DRFs default backends:

.. code-block:: py

    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": [
            ...,
            "zgw_auth_backend.authentication.ZGWAuthentication",
            ...,
        ],
    }


Usage
=====

Specify the authentication class on your view(s):

.. code-block:: py

    from rest_framework import views
    from zgw_auth_backend.authentication import ZGWAuthentication

    class MyView(APIView):
        authentication_classes = (ZGWAuthentication,)


1. Add the client credentials in the admin (client ID + secret)
2. Generate a ZGW auth JWT with the ``user_id`` claim, using the credentials from step 1
3. Make an API call to the endpoint, including the ``Authorization: Bearer <jwt>`` header
4. Verify that the user with ``user_id`` username is created if it didn't exist yet, or
   if it did, that ``request.user`` is now this user.


.. |build-status| image:: https://github.com/maykinmedia/zgw-auth-backend/workflows/Run%20CI/badge.svg
    :target: https://github.com/maykinmedia/zgw-auth-backend/actions?query=workflow%3A%22Run+CI%22
    :alt: Run CI

.. |linting| image:: https://github.com/maykinmedia/zgw-auth-backend/workflows/Code%20quality%20checks/badge.svg
    :target: https://github.com/maykinmedia/zgw-auth-backend/actions?query=workflow%3A%22Code+quality+checks%22
    :alt: Code linting

.. |coverage| image:: https://codecov.io/gh/maykinmedia/zgw-auth-backend/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/maykinmedia/zgw-auth-backend
    :alt: Coverage status

.. |black| image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black

.. |python-versions| image:: https://img.shields.io/pypi/pyversions/zgw-auth-backend.svg

.. |django-versions| image:: https://img.shields.io/pypi/djversions/zgw-auth-backend.svg

.. |pypi-version| image:: https://img.shields.io/pypi/v/zgw-auth-backend.svg
    :target: https://pypi.org/project/zgw-auth-backend/
