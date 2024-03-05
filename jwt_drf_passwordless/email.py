from templated_mail.mail import BaseEmailMessage

from jwt_drf_passwordless.conf import settings


class PasswordlessRequestEmail(BaseEmailMessage):
    template_name = "email/passwordless_request.html"

    def get_context_data(self):
        context = super().get_context_data()
        if settings.PASSWORDLESS_EMAIL_LOGIN_URL:
            # Eg magic links / Deep links for mobile apps
            context["url"] = settings.PASSWORDLESS_EMAIL_LOGIN_URL.format(**context)
        return context
