from rest_framework import authentication, exceptions
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.http import HttpResponse


class TokenAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            user = request.user  # Attempt to get the authenticated user
        except AuthenticationFailed as e:
            # Handle Token Authentication error
            return HttpResponse("Token Authentication failed", status=401)

        response = self.get_response(request)
        return response


class MyAuthentication(authentication.TokenAuthentication):
    def authenticate_credentials(self, key):
        try:
            token = self.model.objects.select_related('user').get(key=key)
        except self.model.DoesNotExist:
            return None, ''

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed('User inactive or deleted.')

        return token.user, token
