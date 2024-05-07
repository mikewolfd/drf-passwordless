from django.contrib.auth import get_user_model
from jwt_drf_passwordless.serializers import PasswordlessTokenService


def create_user(use_custom_data=False, **kwargs):
    data = (
        {
            "username": "john",
            "password": "secret",
            "email": "john@beatles.com",
            "phone_number": "+358414111111",
        }
        if not use_custom_data
        else {
            "custom_username": "john",
            "password": "secret",
            "custom_email": "john@beatles.com",
            "custom_mobile": "+358414111111",
            "custom_required_field": "42",
        }
    )
    data.update(kwargs)
    user = get_user_model().objects.create_user(**data)
    user.raw_password = data["password"]
    return user


def create_token(identifier_field):
    user = create_user()
    return PasswordlessTokenService.create_token(user, identifier_field)
