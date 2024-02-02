from django.contrib import admin
from .models import CustomUser, OTP, PasswordOTP

admin.site.site_title = 'Multi Vendor Admin Panel'
admin.site.site_header = 'Multi Vendor Admin Panel'
admin.site.index_title = 'Welcome to Multi Vendor Admin Panel'

admin.site.register(CustomUser)
admin.site.register(OTP)
admin.site.register(PasswordOTP)