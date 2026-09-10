# SPDX-License-Identifier: MIT
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(
            name="Comment",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("author", models.CharField(default="anon", max_length=80)),
                ("body", models.TextField()),
                ("approved", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["-created_at"]},
        )
    ]
