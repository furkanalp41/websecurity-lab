# SPDX-License-Identifier: MIT
from django.urls import path

from comments import views

urlpatterns = [
    path("health", views.health),
    path("", views.index),
    path("comment", views.post_comment),
    path("admin/moderate", views.moderate),
    path("internal/bot-login", views.bot_login),
    path("oob/received", views.oob_received),
    path("solve", views.solve),
]
