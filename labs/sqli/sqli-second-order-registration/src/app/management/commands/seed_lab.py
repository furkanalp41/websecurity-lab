# SPDX-License-Identifier: MIT
"""Idempotent seed: one admin account with a random per-container session secret,
one benign user, and a couple of referral rows owned by that user."""
import secrets

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from app.models import Account, Referral


class Command(BaseCommand):
    help = "Seed the accounts, users and referrals tables for the lab."

    def handle(self, *args, **options) -> None:
        # Admin secret: NEW random value on every fresh container (the DB lives on
        # a tmpfs, so each run starts empty). This is what the exploit exfiltrates.
        if not Account.objects.filter(username="admin").exists():
            Account.objects.create(
                username="admin",
                session_secret=secrets.token_hex(16),
            )

        # A benign user who owns the seeded referral rows.
        if not User.objects.filter(username="alice").exists():
            User.objects.create_user(
                username="alice",
                password=secrets.token_urlsafe(18),
            )

        if not Referral.objects.exists():
            Referral.objects.create(
                code="REF-2024-8842",
                invited_email="jordan@example.com",
                owner="alice",
            )
            Referral.objects.create(
                code="REF-2024-9931",
                invited_email="samir@example.com",
                owner="alice",
            )

        self.stdout.write("[seed] accounts, user and referrals ready")
