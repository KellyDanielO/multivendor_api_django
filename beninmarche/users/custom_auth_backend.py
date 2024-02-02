from django.contrib.auth.backends import BaseBackend, ModelBackend
from django.db.models import Q
from .models import CustomUser as User


class CustomAuthBackend:
    def authenticate(self, request, email=None, password=None, **kwargs):
        # try:
        #     user = User.objects.get(phone_number=email)
        # except User.DoesNotExist:
        #     return None

        try:
            user = User.objects.get(phone_number=email).first()

            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

        if user.check_password(password):
            return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
