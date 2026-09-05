# SPDX-License-Identifier: MIT
"""URL routing for the referrals lab."""
from django.urls import path

from app import views

urlpatterns = [
    path("", views.index),
    path("health", views.health),
    path("register", views.register),
    path("login", views.login_view),
    path("me/referrals", views.referrals),
    path("solve", views.solve),
]
