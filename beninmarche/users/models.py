from datetime import datetime, timedelta

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
import uuid


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15, blank=True, null=True, unique=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    date_joined = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_vendor = models.BooleanField(default=False)
    id_card_no = models.TextField(blank=True, null=True)
    shop_if_no = models.TextField(blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "phone_number"]

    class Meta:
        ordering = ("date_joined",)
        # verbose_name = "User"
        # verbose_name_plural = "Users"
        # app_label = "account"

        constraints = [
            models.UniqueConstraint(
                fields=["email", "phone_number"],
                name="unique_email_phone",
            )
        ]

    def __str__(self):
        return self.email


class OTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp_value = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    expiration_date = models.DateTimeField(null=True, blank=True)

    def set_expiration_date(self, hours=30):
        future_date = datetime.now() + timezone.timedelta(hours=hours)
        self.expiration_date = future_date
        self.save()

    def __str__(self):
        return "OTP for " + self.user.email + " - " + self.otp_value


class PasswordOTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp_value = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    expiration_date = models.DateTimeField(null=True, blank=True)

    def set_expiration_date(self, hours=30):
        future_date = datetime.now() + timezone.timedelta(hours=hours)
        self.expiration_date = future_date
        self.save()

    def __str__(self):
        return "OTP for " + self.user.email + " - " + self.otp_value
