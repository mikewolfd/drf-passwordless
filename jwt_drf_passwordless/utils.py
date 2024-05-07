from random import SystemRandom
from django.contrib.auth import get_user_model

random = SystemRandom()
User = get_user_model()


def create_challenge(length, challenge_characters):
    return "".join(random.choices(challenge_characters, k=length))


def token_request_limiter(function):
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)

    return wrapper


def token_redeem_limiter(function):
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)

    return wrapper
