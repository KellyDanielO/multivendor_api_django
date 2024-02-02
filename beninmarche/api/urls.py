# baseapp/urls.py
from django.urls import path
from .views import (
    LoginView,
    RegisterView,
    BaseViews,
    SendTestSms,
    OTPVerificationView, CustomTokenRefreshView, ForgottenPassword, MakeUserAVendor, VendorProductView,
    
)

urlpatterns = [
    path('', BaseViews.as_view(), name='base_view'),
    path('login/', LoginView.as_view(), name='login-user'),
    path('register/', RegisterView.as_view(), name='register-user'),
    path('verify-otp/', OTPVerificationView.as_view(), name='verify-otp'),
    path('user/make-vendor/', MakeUserAVendor.as_view(), name='user-make-vendor'),
    # path('test-sms/', SendTestSms.as_view(), name='test-sms'),
    path('token/token-refresh/', CustomTokenRefreshView.as_view(), name='refresh-token'),
    path('user/forgotten-password/', ForgottenPassword.as_view(), name='forgotten-password'),
    path('user/forgotten-password/', ForgottenPassword.as_view(), name='forgotten-password-reset'),
    path('vendor/product/', VendorProductView.as_view(), name='vendor-product'),
    path('vendor/product/<uuid:product_id>/', VendorProductView.as_view(), name='vendor-product-specific'),
]
