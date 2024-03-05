from random import SystemRandom
from typeid import TypeID
from .conf import settings
from django.contrib.auth import get_user_model
random = SystemRandom()
User = get_user_model()

temp_username_prefix = 'temp'

def create_challenge(length, challenge_characters):
    return "".join(random.choices(challenge_characters, k=length))

def username_generator():
    guid = TypeID()
    response =  {User.USERNAME_FIELD: guid.suffix}
    if settings.UUID_FIELD_NAME:
        response[settings.UUID_FIELD_NAME] = guid.uuid
    return response
    
def token_request_limiter(function):
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)
    return wrapper


def token_redeem_limiter(function):
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)

    return wrapper
