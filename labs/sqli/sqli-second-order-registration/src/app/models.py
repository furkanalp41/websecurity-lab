# SPDX-License-Identifier: MIT
"""Lab data model.

`accounts` holds a single admin row whose `session_secret` is randomised per
container by the seed step. `referrals` holds a few benign rows keyed by an
`owner` username string. Registered users live in Django's built-in `auth_user`
table; the `owner` column is compared against a user's stored username.
"""
from django.db import models


class Account(models.Model):
    username = models.CharField(max_length=150, unique=True)
    session_secret = models.CharField(max_length=128)

    class Meta:
        db_table = "accounts"


class Referral(models.Model):
    code = models.CharField(max_length=32)
    invited_email = models.CharField(max_length=254)
    owner = models.CharField(max_length=150)

    class Meta:
        db_table = "referrals"
