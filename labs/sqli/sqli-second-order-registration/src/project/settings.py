# SPDX-License-Identifier: MIT
"""Minimal Django settings for the second-order SQLi referrals lab.

Deliberately small: only the contrib apps needed for session-backed login plus
the one lab app. No admin, no staticfiles, no collectstatic (keeps the image
small and the root filesystem read-only friendly).
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Fixed key supplied via env for the lab (see docker-compose.yml). Not a secret.
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "lab-fixed-insecure-key-second-order-registration-do-not-reuse",
)

DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"

# Wildcard is acceptable for a throwaway, single-tenant lab container.
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "app",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
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

# Password validators intentionally omitted — the lab creates accounts via the
# ORM with arbitrary usernames on purpose (that is the injected, stored value).
AUTH_PASSWORD_VALIDATORS: list[dict[str, str]] = []

LOGIN_URL = "/login"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
