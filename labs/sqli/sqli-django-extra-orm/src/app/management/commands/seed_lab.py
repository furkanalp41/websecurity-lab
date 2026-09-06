# SPDX-License-Identifier: MIT
"""Idempotent seed.

Creates the per-container secret — a Django superuser ``root`` with a RANDOM
password, so its ``pbkdf2_sha256$`` hash in ``auth_user.password`` is unique to
this container — plus a handful of benign products for the search feature.

The random password is never printed or stored anywhere the app can read back;
the ONLY way to learn the hash is to exfiltrate it through the injection. The
stored hash IS the objective: /solve compares the exact hash string.
"""
import secrets

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from app.models import Product

_PRODUCTS = [
    ("Aurora Field Notebook", "Lay-flat dot-grid notebook with a linen cover.", 1899),
    ("Cirrus Travel Mug", "Double-walled 350ml mug that keeps coffee hot for hours.", 2450),
    ("Halcyon Desk Lamp", "Warm-dim LED lamp with a brushed aluminium arm.", 5299),
    ("Meridian Trail Bottle", "Insulated 750ml bottle, leakproof lid, matte finish.", 3200),
    ("Solstice Wool Socks", "Merino crew socks, cushioned heel, three-pack.", 2100),
]


class Command(BaseCommand):
    help = "Seed the products catalogue and the per-container superuser for the lab."

    def handle(self, *args, **options) -> None:
        # Per-container secret: a NEW random superuser password on every fresh
        # container (the DB lives on a tmpfs, so each run starts empty). Its
        # pbkdf2_sha256$ hash is what the exploit exfiltrates from auth_user.
        if not User.objects.filter(username="root").exists():
            User.objects.create_superuser(
                username="root",
                email="root@lab.local",
                password=secrets.token_urlsafe(24),
            )

        if not Product.objects.exists():
            for title, blurb, price_cents in _PRODUCTS:
                Product.objects.create(title=title, blurb=blurb, price_cents=price_cents)

        self.stdout.write("[seed] products and superuser ready")
