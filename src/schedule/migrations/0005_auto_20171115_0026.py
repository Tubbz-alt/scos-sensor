# -*- coding: utf-8 -*-
# Generated by Django 1.11.3 on 2017-11-15 00:26
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('schedule', '0004_scheduleentry_is_private'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scheduleentry',
            name='is_private',
            field=models.BooleanField(default=False, help_text=b'entry and resulting data are only visible to admin'),
        ),
    ]