# baseapp/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.base_view, name='base_view'),
]
