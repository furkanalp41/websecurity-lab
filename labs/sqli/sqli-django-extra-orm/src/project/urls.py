# SPDX-License-Identifier: MIT
"""URL routing for the advanced-search lab."""
from django.urls import path

from app import views

urlpatterns = [
    path("", views.index),
    path("health", views.health),
    path("search", views.search),
    path("solve", views.solve),
]
