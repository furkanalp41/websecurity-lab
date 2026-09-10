# SPDX-License-Identifier: MIT
"""Minimal Django settings for the stored-XSS blog lab."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "lab-insecure-key-not-a-flag")
DEBUG = False
ALLOWED_HOSTS = ["*"]  # lab-internal; the app is only reachable on loopback/backend

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
    "comments",
]

# Deliberately minimal: no SessionMiddleware/auth/CSRF. The admin "session" is a
# plain cookie the app mints for the bot, and the public comment endpoint is
# csrf_exempt so an attacker can post a comment with a bare HTTP request — which
# is the whole point of a stored-XSS lab.
MIDDLEWARE = ["django.middleware.common.CommonMiddleware"]

ROOT_URLCONF = "blog.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,  # loads comments/templates/*
        "OPTIONS": {"context_processors": []},
    }
]

WSGI_APPLICATION = "blog.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DB_NAME", "blog"),
        "USER": os.environ.get("DB_USER", "blog"),
        "PASSWORD": os.environ.get("DB_PASSWORD", ""),
        "HOST": os.environ.get("DB_HOST", "db"),
        "PORT": os.environ.get("DB_PORT", "5432"),
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
STATIC_URL = "/static/"
USE_TZ = True
