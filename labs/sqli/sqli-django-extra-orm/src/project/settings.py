# SPDX-License-Identifier: MIT
"""Minimal Django settings for the .extra() advanced-search SQLi lab.

Deliberately small: only the contrib apps needed to own the ``auth_user`` table
(the injection target) plus the one lab app. No admin, no sessions, no
staticfiles, no collectstatic — keeps the image small and the read-only root
filesystem happy.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Fixed key supplied via env for the lab (see docker-compose.yml). Not a secret.
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "lab-fixed-insecure-key-django-extra-orm-do-not-reuse",
)

DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"

# Wildcard is acceptable for a throwaway, single-tenant lab container.
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "app",
]

# No SessionMiddleware / AuthenticationMiddleware: the lab has no login flow.
# The auth app is installed only so the ``auth_user`` table exists to hold the
# per-container superuser whose password hash the injection exfiltrates.
MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

ROOT_URLCONF = "project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": False,
        "OPTIONS": {"context_processors": []},
    }
]

WSGI_APPLICATION = "project.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DB_NAME", "app_db"),
        "USER": os.environ.get("DB_USER", "appuser"),
        "PASSWORD": os.environ.get("DB_PASSWORD", ""),
        "HOST": os.environ.get("DB_HOST", "db"),
        "PORT": os.environ.get("DB_PORT", "5432"),
    }
}

# Default Django password validators/hashers apply: the seeded superuser gets a
# standard pbkdf2_sha256$ hash, which is exactly what the injection reads out.
AUTH_PASSWORD_VALIDATORS: list[dict[str, str]] = []

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
