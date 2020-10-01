from django.conf import settings

token_auth_enabled = "rest_framework.authentication.TokenAuthentication" in settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]
oauth_jwt_authentication_enabled = "authentication.auth.OAuthJWTAuthentication" in settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]

def jwt_request_has_required_role(request):
    if request.auth:
        authorities = request.auth["authorities"]
        return settings.REQUIRED_ROLE in authorities
    return False