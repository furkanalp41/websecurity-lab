# SPDX-License-Identifier: MIT
"""Lab data model.

``products`` is a small catalogue the "advanced search" feature queries. The
model has exactly four selected columns (``id``, ``title``, ``blurb``,
``price_cents``); that column count is what a UNION-based injection must match.

The value the exploit exfiltrates does NOT live here: it is the per-container
superuser password hash in Django's built-in ``auth_user`` table, reachable
only because the raw ``.extra()`` clause lets an attacker UNION across tables.
"""
from django.db import models


class Product(models.Model):
    title = models.CharField(max_length=200)
    blurb = models.TextField()
    price_cents = models.IntegerField()

    class Meta:
        db_table = "app_product"
