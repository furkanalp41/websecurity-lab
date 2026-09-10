# SPDX-License-Identifier: MIT
from django.db import models


class Comment(models.Model):
    author = models.CharField(max_length=80, default="anon")
    body = models.TextField()
    approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
