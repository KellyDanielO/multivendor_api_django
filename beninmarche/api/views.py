import random
import string
from datetime import datetime

from django.contrib.auth import login
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.core.mail import send_mail
from django.utils import timezone
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import authentication_classes, permission_classes
# Token imports
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser
from twilio.rest import Client
# User model
from users.models import CustomUser as User
from users.models import OTP, PasswordOTP

from .models import Product
from .my_functions import check_email_existence, check_phone_number_existence, is_valid_email, is_phone_number, \
    sendOTPMessagePhoneNumber
from .serializers import UserSerializer, ProductSerializer


class BaseViews(APIView):
    def get(self, request):
        data = {'message': 'Welcome to the Multi Vendor API!'}
        return Response(data)


# Login existing user
class LoginView(APIView):

    @swagger_auto_schema(
        operation_description="Login User and vendor into Multi Vendor",
        responses={
            200: "successful",
            400: "key fields are missing",
            401: "invalid credentials",
        },
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email_or_phone', 'password'],
            properties={
                'email_or_phone': openapi.Schema(type=openapi.TYPE_STRING, description='Email or Phone Number'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='User Email',
                                           format=openapi.FORMAT_PASSWORD)
            }
        ),
    )
    def post(self, request):
        email_or_phone = request.data.get('email_or_phone')
        password = request.data.get('password')

        if email_or_phone is None or email_or_phone == '' or password == '' or password is None:
            return Response({'error': 'key fields are missing',
                             }, status=status.HTTP_400_BAD_REQUEST)

        user = None
        if is_valid_email(email_or_phone):
            user = User.objects.get(email=email_or_phone)
        else:
            user = User.objects.get(phone_number=email_or_phone)
        if user is not None:
            if not user.check_password(password):
                return Response({'error': 'invalid password'}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                login(request, user)
                refresh = RefreshToken.for_user(user)
                serializer = UserSerializer(user)
                return Response({'response': 'successful',
                                 'access': str(refresh.access_token),
                                 'refresh': str(refresh),
                                 'user': serializer.data
                                 }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


# Convert user account to a vendor account
class MakeUserAVendor(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Mark user a vendor",
        responses={
            200: "success",
            400: "key fields are missing",
            401: 'user does not exist'
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="JWT token for authentication",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['id_card_no', 'shop_if_no'],
            properties={
                'id_card_no': openapi.Schema(type=openapi.TYPE_STRING, description='OTP'),
                'shop_if_no': openapi.Schema(type=openapi.TYPE_STRING, description='OTP'),
            }
        ),
    )
    def put(self, request):
        id_card_no = request.data.get('id_card_no')
        shop_if_no = request.data.get('shop_if_no')

        if shop_if_no is None or shop_if_no == '' or id_card_no is None or id_card_no == '':
            return Response({
                'error': 'key fields are missing'
            }, status=status.HTTP_400_BAD_REQUEST)
        else:
            user = request.user
            try:
                instance = User.objects.get(id=user.id)
                instance.id_card_no = id_card_no
                instance.shop_if_no = shop_if_no
                instance.is_vendor = True
                instance.save()
                return Response({"response": "User now a vendor"}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"response": "User does not exists"}, status=status.HTTP_401_UNAUTHORIZED)


# Register new user
class RegisterView(APIView):
    @swagger_auto_schema(
        operation_description="Register user and vendor into Multi Vendor",
        responses={
            201: "OTP sent",
            200: "Account created but OTP not sent",
            400: "key fields are missing or invalid data sent",
            401: "email or phone number exists",
            406: "invalid password",
        },
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['full_name', 'location', 'email_or_phone', 'password'],
            properties={
                'full_name': openapi.Schema(type=openapi.TYPE_STRING, description='Full Name',
                                           format=openapi.FORMAT_PASSWORD),
                'location': openapi.Schema(type=openapi.TYPE_STRING, description='Location',
                                           format=openapi.FORMAT_PASSWORD),
                'email_or_phone': openapi.Schema(type=openapi.TYPE_STRING, description='Email or Phone Number'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='User Email',
                                           format=openapi.FORMAT_PASSWORD),
            }
        ),
    )
    def post(self, request):
        email_or_password = request.data.get('email_or_phone')
        password = request.data.get('password')
        full_name = request.data.get('full_name')
        location = request.data.get('location')

        if email_or_password is None or password is None or full_name is None or location is None:
            return Response({
                'error': 'key fields are missing'
            }, status=status.HTTP_400_BAD_REQUEST)
        else:
            try:
                validate_password(password, User)
            except ValidationError as e:
                return Response({"error": e}, status=status.HTTP_406_NOT_ACCEPTABLE)
            if is_valid_email(email_or_password):
                if check_email_existence(email_or_password):
                    return Response({
                        'error': 'email exists'
                    }, status=status.HTTP_400_BAD_REQUEST)
                else:
                    user = User(email=email_or_password, name=full_name)
                    user.set_password(password)
                    user.save()

                    otp_value = ''.join(random.choices(string.digits, k=6))
                    otp = OTP.objects.create(user=user, otp_value=otp_value)
                    otp.set_expiration_date(hours=1)

                    # Send the OTP to the user's email
                    subject = 'Your OTP for Multi Vendor Registration'
                    message = f'Your OTP is: {otp_value}'
                    from_email = 'kellydacodingmaestro@gmail.com'  # Use a valid email address
                    recipient_list = [user.email]

                    send_mail(subject, message, from_email, recipient_list)

                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'response': 'otp sent to email',
                        'access': str(refresh.access_token),
                        'refresh': str(refresh)
                    }, status=status.HTTP_201_CREATED)
            elif is_phone_number(email_or_password):
                if check_phone_number_existence(email_or_password):
                    return Response({
                        'error': 'phone number exists'
                    }, status=status.HTTP_401_UNAUTHORIZED)
                else:
                    user = User(email='example@gmail.com', name=full_name, phone_number=email_or_password)
                    user.set_password(password)
                    user.save()

                    otp_value = ''.join(random.choices(string.digits, k=6))
                    otp = OTP.objects.create(user=user, otp_value=otp_value)
                    otp.set_expiration_date(hours=1)

                    # Send the OTP to the user's email
                    subject = 'Your OTP for Multi Vendor Registration'
                    message = f'Your OTP is: {otp_value}'
                    from_number = '+12295261873'  # Use a valid email address
                    to_number = [user.phone_number]

                    send_message = sendOTPMessagePhoneNumber(to_number, from_number, message)

                    if send_message:
                        refresh = RefreshToken.for_user(user)
                        return Response({
                            'response': 'otp sent to phone number',
                            'access': str(refresh.access_token),
                            'refresh': str(refresh)
                        }, status=status.HTTP_201_CREATED)
                    else:
                        refresh = RefreshToken.for_user(user)
                        return Response({
                            'response': 'otp was not sent to phone number',
                            'access': str(refresh.access_token),
                            'refresh': str(refresh)
                        }, status=status.HTTP_200_OK)

            else:
                return Response({
                    'error': 'not email or phone number'
                }, status=status.HTTP_400_BAD_REQUEST)


# Verify OTP
class OTPVerificationView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="OTP verification",
        responses={
            201: "OTP sent to E-mail",
            200: "OTP verified",
            400: "key fields are missing or invalid data sent",
            401: "email or phone number exists",
            406: "unknown error",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="JWT token for authentication",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['otp'],
            properties={
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='OTP'),
            }
        ),
    )
    def post(self, request):
        otp_value = request.data.get('otp')
        user = request.user
        try:

            otp_model = OTP.objects.get(user=user)
            if otp_model.otp_value != otp_value:
                return Response({
                    'error': 'invalid OTP code'
                }, status=status.HTTP_406_NOT_ACCEPTABLE)
            elif otp_model.is_verified:
                return Response({'response': 'otp already verified'},
                                status=status.HTTP_200_OK)
            elif timezone.make_aware(datetime.now()) > otp_model.expiration_date:
                otp_model.delete()
                otp_value = ''.join(random.choices(string.digits, k=6))
                otp = OTP.objects.create(user=user, otp_value=otp_value)
                otp.set_expiration_date(hours=1)

                subject = 'Your OTP for Multi Vendor Registration'
                message = f'Your OTP is: {otp_value}'
                from_email = 'kellydacodingmaestro@gmail.com'  # Use a valid email address
                recipient_list = [user.email]

                send_mail(subject, message, from_email, recipient_list)

                return Response({'response': 'otp expired, new otp created check email'},
                                status=status.HTTP_201_CREATED)
            elif otp_model.otp_value == otp_value and timezone.make_aware(
                    datetime.now()) < otp_model.expiration_date and otp_model.is_verified is not True:
                otp_model.is_verified = True
                otp_model.save()
                return Response({'response': 'otp verification successful'},
                                status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'unknown'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except ObjectDoesNotExist:
            otp_value = ''.join(random.choices(string.digits, k=6))
            otp = OTP.objects.create(user=user, otp_value=otp_value)
            otp.set_expiration_date(hours=1)

            subject = 'Your OTP for Multi Vendor Registration'
            message = f'Your OTP is: {otp_value}'
            from_email = 'kellydacodingmaestro@gmail.com'  # Use a valid email address
            recipient_list = [user.email]

            send_mail(subject, message, from_email, recipient_list)

            return Response({'response': 'new otp created check email'}, status=status.HTTP_201_CREATED)


class SendTestSms(APIView):
    def post(self, request):
        account_sid = 'ACf87e6ba6446edea368145e19c7766dce'
        auth_token = '7c09c2d0feff63a38280c2b3f057cc68'
        # account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
        # auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
        try:
            client = Client(account_sid, auth_token)

            # to = request.POST.get('to')
            to = '+2348067081323'
            from_ = '+12295261873'
            body = request.POST.get('body', 'Default SMS body')

            message = client.messages.create(
                to=to,
                from_=from_,
                body=body
            )
            return Response({'message': str(message)})
        except Exception as e:
            print(e)
            return Response({'error': 'true'}, status=status.HTTP_400_BAD_REQUEST)


# To check token validity
class TestToken(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="To check if authentication is working",
        responses={200: openapi.Response("This is to check if authentication is working",
                                         openapi.Schema(type=openapi.TYPE_OBJECT))}
    )
    def get(self, request):
        return Response("token passed for {}".format(request.user.email))


# get a new access token
class CustomTokenRefreshView(APIView):

    @swagger_auto_schema(
        operation_description="Get a new refresh token",
        responses={
            200: "success",
            400: "refresh token is required",
            401: "invalid refresh token",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="JWT token for authentication",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['otp'],
            properties={
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='OTP'),
            }
        ),
    )
    def post(self, request):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            return Response({'access_token': access_token}, status=status.HTTP_200_OK)
        except RefreshToken.DoesNotExist:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)


# Forgotten password
class ForgottenPassword(APIView):

    @swagger_auto_schema(
        operation_description="Forgotten password: here you'll reset password with the following fields",
        responses={
            200: "success",
            201: "new OTP sent",
            400: "key fields are missing",
            406: 'invalid OTP code',
            405: 'invalid password format',
            409: 'error unknown'
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="JWT token for authentication",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['otp', 'password'],
            properties={
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='OTP'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='password',
                                           format=openapi.FORMAT_PASSWORD),
            }
        ),
    )
    @authentication_classes([TokenAuthentication])
    @permission_classes([IsAuthenticated])
    def put(self, request):
        otp_value = request.data.get('otp')
        new_password = request.data.get('password')

        user = request.user

        if otp_value is None or otp_value == '' or new_password == '' or new_password is None:
            return Response({"error": "All fields is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            otp_model = PasswordOTP.objects.get(user=user)
            if otp_model.otp_value != otp_value:
                return Response({
                    'error': 'invalid OTP code'
                }, status=status.HTTP_406_NOT_ACCEPTABLE)
            elif otp_model.is_verified:
                otp_model.delete()
                otp_value = ''.join(random.choices(string.digits, k=4))
                otp = PasswordOTP.objects.create(user=user, otp_value=otp_value)
                otp.set_expiration_date(hours=1)

                subject = 'Your OTP for Multi Vendor Password Rest'
                message = (f'Your OTP is: {otp_value}\nInput this OTP code in the input field provided.\nThis OTP will '
                           f'expire in 1 hour')
                from_email = 'kellydacodingmaestro@gmail.com'  # Use a valid email address
                recipient_list = [user.email]

                send_mail(subject, message, from_email, recipient_list)

                return Response({'response': 'otp already verified, new otp created check email'},
                                status=status.HTTP_201_CREATED)
            elif timezone.make_aware(datetime.now()) > otp_model.expiration_date:
                otp_model.delete()
                otp_value = ''.join(random.choices(string.digits, k=4))
                otp = PasswordOTP.objects.create(user=user, otp_value=otp_value)
                otp.set_expiration_date(hours=1)

                subject = 'Your OTP for Multi Vendor Password Rest'
                message = (f'Your OTP is: {otp_value}\nInput this OTP code in the input field provided.\nThis OTP will '
                           f'expire in 1 hour')
                from_email = 'kellydacodingmaestro@gmail.com'  # Use a valid email address
                recipient_list = [user.email]

                send_mail(subject, message, from_email, recipient_list)

                return Response({'response': 'otp expired, new otp created check email'},
                                status=status.HTTP_201_CREATED)
            elif otp_model.otp_value == otp_value and timezone.make_aware(
                    datetime.now()) < otp_model.expiration_date and otp_model.is_verified is not True:

                # Validate password complexity
                try:
                    validate_password(new_password, User)
                except ValidationError as e:
                    return Response({"error": e}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

                user.password = make_password(new_password)
                user.save()
                otp_model.is_verified = True
                otp_model.save()
                return Response({'response': 'password reset successful'},
                                status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'unknown'
                }, status=status.HTTP_409_CONFLICT)

        except ObjectDoesNotExist:
            otp_value = ''.join(random.choices(string.digits, k=4))
            otp = PasswordOTP.objects.create(user=user, otp_value=otp_value)
            otp.set_expiration_date(hours=1)

            subject = 'Your OTP for Multi Vendor Password Rest'
            message = (f'Your OTP is: {otp_value}\nInput this OTP code in the input field provided.\nThis OTP will '
                       f'expire in 1 hour')
            from_email = 'kellydacodingmaestro@gmail.com'  # Use a valid email address
            recipient_list = [user.email]

            send_mail(subject, message, from_email, recipient_list)

            return Response({'response': 'new otp created check email'}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        operation_description="Forgotten password: to get an OTP code to reset your password",
        responses={
            201: "new OTP sent",
            400: "key fields are missing",
            401: "email or phone number not found",
            409: 'not email or phone number'
        },
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email_or_phone'],
            properties={
                'email_or_phone': openapi.Schema(type=openapi.TYPE_STRING, description='email_or_phone')
            }
        ),
    )
    @permission_classes([AllowAny])
    def post(self, request):
        email_or_phone = request.data.get('email_or_phone')

        if email_or_phone is None or email_or_phone == '':
            return Response({'error': 'key field missing'}, status=status.HTTP_400_BAD_REQUEST)

        if is_valid_email(email_or_phone):
            try:
                user = User.objects.get(email=email_or_phone)
                otp_value = ''.join(random.choices(string.digits, k=4))
                queryset_to_delete = PasswordOTP.objects.filter(user=user)
                queryset_to_delete.delete()

                otp = PasswordOTP.objects.create(user=user, otp_value=otp_value)
                otp.set_expiration_date(hours=1)

                subject = 'Your OTP for Multi Vendor Password Rest'
                message = (f'Your OTP is: {otp_value}\nInput this OTP code in the input field provided.\nThis OTP will '
                           f'expire in 1 hour')
                from_email = 'kellydacodingmaestro@gmail.com'  # Use a valid email address
                recipient_list = [user.email]

                send_mail(subject, message, from_email, recipient_list)

                refresh = RefreshToken.for_user(user)

                return Response({'response': 'otp sent',
                                 'access_token': str(refresh.access_token),
                                 'refresh_token': str(refresh)}, status=status.HTTP_201_CREATED)
            except User.DoesNotExist:
                return Response({'error': 'email not found'}, status=status.HTTP_401_UNAUTHORIZED)
        elif is_phone_number(email_or_phone):
            try:
                user = User.objects.get(phone_number=email_or_phone)
                otp_value = ''.join(random.choices(string.digits, k=4))
                print(otp_value)
                queryset_to_delete = PasswordOTP.objects.filter(user=user)
                queryset_to_delete.delete()

                otp = PasswordOTP.objects.create(user=user, otp_value=otp_value)
                otp.set_expiration_date(hours=1)

                subject = 'Your OTP for Multi Vendor Password Rest'
                message = (f'Your OTP is: {otp_value}\nInput this OTP code in the input field provided.\nThis OTP will '
                           f'expire in 1 hour')
                from_number = '+12295261873'  # Use a valid email address
                to_number = [user.phone_number]

                send_message = sendOTPMessagePhoneNumber(to_number, from_number, message)

                refresh = RefreshToken.for_user(user)

                return Response({'response': 'otp sent',
                                 'access_token': str(refresh.access_token),
                                 'refresh_token': str(refresh)}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'error': 'phone number not found'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({
                'error': 'not email or phone number'
            }, status=status.HTTP_409_CONFLICT)


# Vendor Product Management
class VendorProductView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get All Products or A Single Product",
        responses={
            200: "done",
            404: 'not found',
            400: 'error unknown'
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="JWT token for authentication",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ]
    )
    def get(self, request, product_id=None):
        user = request.user
        if product_id is None:
            try:
                products = user.product_set.all().order_by('-date_created')
                serializer = ProductSerializer(products, many=True)
                return Response({'response': 'done', 'products': serializer.data, }, status=status.HTTP_200_OK)
            except ObjectDoesNotExist:
                return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                print(e)
                return Response({"error": "unexpected error"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            try:
                products = user.product_set.get(product_id=product_id)
                serializer = ProductSerializer(products)
                return Response({'response': 'done', 'product': serializer.data, }, status=status.HTTP_200_OK)
            except ObjectDoesNotExist:
                return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"error": "unexpected error"}, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Create a new product",
        responses={
            201: "created",
            400: "key fields are missing",
            409: 'validation error',
            406: 'you are not a vendor',
            500: 'error unknown'
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="JWT token for authentication",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['product_name', 'listing_tags', 'status', 'price', 'price_options', 'phone_number',
                      'description', 'address'],
            properties={
                'product_name': openapi.Schema(type=openapi.TYPE_STRING, description='Product Name'),
                'listing_tags': openapi.Schema(type=openapi.TYPE_STRING, description='listing tags'),
                'status': openapi.Schema(type=openapi.TYPE_STRING, description='status'),
                'price': openapi.Schema(type=openapi.TYPE_STRING, description='price'),
                'price_options': openapi.Schema(type=openapi.TYPE_STRING, description='price options'),
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='phone number'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='email'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='description'),
                'address': openapi.Schema(type=openapi.TYPE_STRING, description='address'),
            }
        ),
    )
    def post(self, request, product_id=None):
        product_name = request.data.get('product_name')
        listing_tags = request.data.get('listing_tags')
        status_ = request.data.get('status')
        price = request.data.get('price')
        price_options = request.data.get('price_options')
        phone_number = request.data.get('phone_number')
        email = request.data.get('email')
        description = request.data.get('description')
        address = request.data.get('address')

        if (product_name is None or product_name == '' or listing_tags is None or listing_tags == '' or status_ is None
                or status_ == '' or price is None or price == '' or price_options is None or price_options == '' or
                phone_number is None or phone_number == '' or description is None or description == '' or
                address is None or address == ''):
            return Response({
                'error': 'key fields are missing'
            }, status=status.HTTP_400_BAD_REQUEST)
        else:
            user = request.user
            if user.is_vendor:
                try:
                    product = Product(product_name=product_name, listing_tags=listing_tags, status=status_, price=price,
                                      price_options=price_options, phone_number=phone_number, email=email,
                                      description=description, address=address, user=user)
                    product.full_clean()
                    product.save()
                    return Response({"response": "successful"}, status=status.HTTP_201_CREATED)
                except ValidationError as ve:
                    print(ve)
                    return Response({"error": "Validation error"}, status=status.HTTP_409_CONFLICT)
                except Exception as e:
                    return Response({"error": "unexpected error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({
                    'error': 'you are not a vendor'
                }, status=status.HTTP_406_NOT_ACCEPTABLE)

    @swagger_auto_schema(
        operation_description="Delete a product",
        responses={
            200: "deleted",
            400: "key fields are missing",
            500: 'error unknown'
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="JWT token for authentication",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ]
    )
    def delete(self, request, product_id=None):
        user = request.user

        if product_id is None:
            deleted_count, _ = Product.objects.filter(user=user).delete()
            if deleted_count == 0:
                return Response({"response": "error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({"response": "deleted"}, status=status.HTTP_200_OK)
        else:
            deleted_count, _ = Product.objects.filter(user=user, product_id=product_id).delete()
            if deleted_count == 0:
                return Response({"response": "error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({"response": "deleted"}, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_description="Update a product",
        responses={
            200: "updated",
            400: "key fields are missing",
            500: 'error unknown'
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="JWT token for authentication",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['product_name', 'listing_tags', 'status', 'price', 'price_options', 'phone_number',
                      'description', 'address'],
            properties={
                'product_name': openapi.Schema(type=openapi.TYPE_STRING, description='Product Name'),
                'listing_tags': openapi.Schema(type=openapi.TYPE_STRING, description='listing tags'),
                'status': openapi.Schema(type=openapi.TYPE_STRING, description='status'),
                'price': openapi.Schema(type=openapi.TYPE_STRING, description='price'),
                'price_options': openapi.Schema(type=openapi.TYPE_STRING, description='price options'),
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='phone number'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='email'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='description'),
                'address': openapi.Schema(type=openapi.TYPE_STRING, description='address'),
            }
        ),
    )
    def put(self, request, product_id=None):
        if product_id is None:
            return Response({"response": "no product id"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            product_name = request.data.get('product_name')
            listing_tags = request.data.get('listing_tags')
            status_ = request.data.get('status')
            price = request.data.get('price')
            price_options = request.data.get('price_options')
            phone_number = request.data.get('phone_number')
            email = request.data.get('email')
            description = request.data.get('description')
            address = request.data.get('address')

            user = request.user

            try:
                instance = Product.objects.get(product_id=product_id, user=user)
                instance.product_name = product_name
                instance.listing_tags = listing_tags
                instance.status = status_
                instance.price = price
                instance.price_options = price_options
                instance.phone_number = phone_number
                instance.email = email
                instance.description = description
                instance.address = address
                instance.save()
                return Response({"response": "updated"}, status=status.HTTP_200_OK)
            except Product.DoesNotExist:
                return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)

