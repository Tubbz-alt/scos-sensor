from rest_framework import permissions
from django.conf import settings
from .auth import token_auth_enabled, oauth_jwt_authentication_enabled, jwt_request_has_required_role

class TokenAuthenticationEnabledPermission(permissions.BasePermission):
    message = "Token Authentication is not enabled"

    def has_permission(self, request, view):
        return token_auth_enabled

class RequiredJWTRolePermissionOrIsSuperuser(permissions.BasePermission):
    message = "User missing required role"

    def has_permission(self, request, view):
        if oauth_jwt_authentication_enabled and jwt_request_has_required_role(request):
            return True
        if request.user.is_superuser:
            return True
        return False