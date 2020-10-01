from rest_framework import permissions
from django.conf import settings
from .utils import jwt_request_has_required_role, token_auth_enabled, oauth_jwt_authentication_enabled


class TokenAuthenticationEnabledPermission(permissions.BasePermission):
    message = "Token Authentication is not enabled"

    def has_permission(self, request, view):
        return token_auth_enabled

class RequiredJWTRolePermission(permissions.BasePermission):
    message = "User missing required role"

    def has_permission(self, request, view):
        return oauth_jwt_authentication_enabled and jwt_request_has_required_role(request)