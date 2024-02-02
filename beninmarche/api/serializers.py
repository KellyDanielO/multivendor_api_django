from rest_framework import serializers
from users.models import CustomUser
from .models import Product


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'name', 'phone_number', 'location', 'date_joined', 'is_staff', 'is_vendor',
                  'id_card_no', 'shop_if_no']
        # fields = '__all__'


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'


