from django.dispatch import Signal

# User has activated his or her account. Args: user, request.
user_activated = Signal()
