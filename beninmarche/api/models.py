import uuid

from django.utils import timezone

from django.db import models
from users.models import CustomUser as User


class Product(models.Model):
    product_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    product_name = models.CharField(max_length=300, null=False, blank=False)
    listing_tags = models.CharField(max_length=300, null=False, blank=False)
    status = models.CharField(max_length=300, null=False, blank=False)
    price = models.CharField(max_length=25, blank=False, null=False)
    price_options = models.CharField(max_length=300, null=False, blank=False)
    phone_number = models.CharField(max_length=15, blank=False, null=False)
    email = models.EmailField(null=True, blank=True)
    description = models.TextField(null=False, blank=False)
    address = models.TextField(null=False, blank=False)
    date_created = models.DateTimeField(default=timezone.now)

    user = models.ForeignKey(User, on_delete=models.CASCADE, null=False, blank=False)

    def __str__(self):
        return str(self.product_name) + ' - ' + str(self.date_created)


