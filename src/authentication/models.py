from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from .utils import token_auth_enabled

class User(AbstractUser):
    """A user of the sensor."""

    email = models.EmailField(null=True)


@receiver(post_save, sender=User)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    """When a new user is created, generate a token for the account."""
    if token_auth_enabled and created:
        Token.objects.create(user=instance)


@receiver(pre_save, sender=User)
def set_unusable_password(sender, instance=None, created=False, **kwargs):
    """When a non-admin user is created, explicitly set unusable password."""
    if created:
        if (not token_auth_enabled) or (token_auth_enabled and not instance.is_staff):
            instance.set_unusable_password()
