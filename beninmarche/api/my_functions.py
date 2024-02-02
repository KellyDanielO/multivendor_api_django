from users.models import CustomUser
import re
from validate_email import validate_email
from twilio.rest import Client


def check_email_existence(email):
    return CustomUser.objects.filter(email=email).exists()


def check_phone_number_existence(phone_number):
    return CustomUser.objects.filter(phone_number=phone_number).exists()


#
# def is_valid_email(email):
#     return validate_email(email, verify=True)
def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None


def is_phone_number(phone_number):
    if len(phone_number) > 16 or len(phone_number) < 9:
        return False
    else:
        pattern = r'^[+]*[(]{0,1}[0-9]{1,4}[)]{0,1}[-\s\./0-9]*$'
        return re.match(pattern, phone_number) is not None



def sendOTPMessagePhoneNumber(to_number, from_number, body):
    account_sid = 'ACf87e6ba6446edea368145e19c7766dce'
    auth_token = '7c09c2d0feff63a38280c2b3f057cc68'

    try:
        client = Client(account_sid, auth_token)
        
        message = client.messages.create(
            to=to_number,
            from_=from_number,
            body=body
        )

        return True
    except:
      return False