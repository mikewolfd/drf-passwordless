from django.contrib.auth import get_user_model
from djet import assertions
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from .common import create_token, create_user
from django.conf import settings
from django.test.utils import override_settings
from jwt_drf_passwordless.conf import settings as JWT_DRF_PASSWORDLESS_settings
from django.utils import timezone
from datetime import timedelta
from unittest import mock
from django.core import mail
import re


User = get_user_model()


class TestPasswordlessEmailTokenExchange(
    APITestCase, assertions.StatusCodeAssertionsMixin
):
    url = reverse("email_passwordless_token_exchange")

    def test_should_fail_with_dummy_token(self):
        token = create_token("email")
        data = {"token": "fuck", "email": token.user.email}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)

    def test_should_fail_with_without_email(self):
        token = create_token("email")
        data = {"token": token.short_token}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)

    def test_should_accept_short_token_with_email(self):
        token = create_token("email")
        data = {"token": token.short_token, "email": token.user.email}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)

    def test_should_return_jwt_token_with_email(self):
        token = create_token("email")
        data = {"token": token.short_token, "email": token.user.email}
        response = self.client.post(self.url, data=data)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS, **{"MAX_TOKEN_USES": 1}
        )
    )
    def test_should_allow_redeeming_token_only_1_times(self):
        token = create_token("email")
        data = {"token": token.short_token, "email": token.user.email}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS, **{"MAX_TOKEN_USES": 2}
        )
    )
    def test_should_allow_redeeming_token_only_2_times(self):
        token = create_token("email")
        data = {"token": token.short_token, "email": token.user.email}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS,
            **{
                "INCORRECT_SHORT_TOKEN_REDEEMS_TOKEN": True,
            },
        )
    )
    def test_redeeming_wrong_token_redeems_it_if_configured(self):
        token = create_token("email")
        data = {"token": "bad-token", "email": token.user.email}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        token.refresh_from_db()
        self.assertEqual(token.uses, 2)

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS,
            **{"INCORRECT_SHORT_TOKEN_REDEEMS_TOKEN": False},
        )
    )
    def test_redeeming_wrong_token_does_not_redeem_it_if_configured(self):
        token = create_token("email")
        data = {"token": "bad-token", "email": token.user.email}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        token.refresh_from_db()
        self.assertEqual(token.uses, 0)

    def test_redeeming_expired_token_does_not_work(self):
        past_time = timezone.now() - timedelta(
            seconds=JWT_DRF_PASSWORDLESS_settings.TOKEN_LIFETIME + 1
        )

        with mock.patch("django.utils.timezone.now", mock.Mock(return_value=past_time)):
            # Create a toke in the past
            token = create_token("email")

        data = {"token": token.short_token, "email": token.user.email}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS,
            **{"INCORRECT_SHORT_TOKEN_REDEEMS_TOKEN": True, "MAX_TOKEN_USES": 1},
        )
    )
    def test_redeeming_expired_token_dsoes_not_work(self):
        future = timezone.now() + timedelta(
            seconds=JWT_DRF_PASSWORDLESS_settings.TOKEN_LIFETIME + 1
        )
        user = create_user()
        data = {"email": user.email}

        # with mock.patch("django.utils.timezone.now", mock.Mock(return_value=past_time)):
        # Create a toke in the past
        response = self.client.post(
            reverse("passwordless_email_signup_request"), data=data
        )
        response2 = self.client.post(
            reverse("passwordless_email_signup_request"), data=data
        )
        self.assert_status_equal(response2, status.HTTP_429_TOO_MANY_REQUESTS)
        data = {"token": 123456, "email": user.email}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        token = mail.outbox[-1].body
        # Find 6 digits in the token body
        match = re.search(r"\d{6}", token)
        if match:
            token = match.group()
        else:
            raise Exception("No 6 digit number found in token")
        data = {"token": token, "email": user.email}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(
            reverse("passwordless_email_signup_request"), data=data
        )
        self.assert_status_equal(response, status.HTTP_429_TOO_MANY_REQUESTS)
        with mock.patch("jwt_drf_passwordless.services.now") as mock_date:
            mock_date.return_value = future
            response = self.client.post(
                reverse("passwordless_email_signup_request"), data=data
            )
            self.assert_status_equal(response, status.HTTP_200_OK)
        token = mail.outbox[-1].body
        # Find 6 digits in the token body
        match = re.search(r"\d{6}", token)
        if match:
            token = match.group()
        else:
            raise Exception("No 6 digit number found in token")
        data = {"token": token, "email": user.email}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)


class TestPasswordlessMobileTokenExchange(
    APITestCase, assertions.StatusCodeAssertionsMixin
):
    url = reverse("mobile_passwordless_token_exchange")

    def test_should_fail_with_dummy_token(self):
        token = create_token("phone_number")
        data = {"token": "fuck", "phone_number": token.user.phone_number}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)

    def test_should_fail_with_without_phone_number(self):
        token = create_token("phone_number")
        data = {"token": token.short_token}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)

    def test_should_accept_short_token_with_phone_number(self):
        token = create_token("phone_number")
        data = {"token": token.short_token, "phone_number": token.user.phone_number}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)

    def test_should_return_jwt_token_with_phone_number(self):
        token = create_token("phone_number")
        data = {"token": token.short_token, "phone_number": token.user.phone_number}
        response = self.client.post(self.url, data=data)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS, **{"MAX_TOKEN_USES": 1}
        )
    )
    def test_should_allow_redeeming_token_only_1_times(self):
        token = create_token("phone_number")
        data = {"token": token.short_token, "phone_number": token.user.phone_number}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS, **{"MAX_TOKEN_USES": 2}
        )
    )
    def test_should_allow_redeeming_token_only_2_times(self):
        token = create_token("phone_number")
        data = {"token": token.short_token, "phone_number": token.user.phone_number}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS,
            **{"INCORRECT_SHORT_TOKEN_REDEEMS_TOKEN": True},
        )
    )
    def test_redeeming_wrong_token_redeems_it_if_configured(self):
        token = create_token("phone_number")
        data = {"token": "bad-token", "phone_number": token.user.phone_number}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        token.refresh_from_db()
        self.assertEqual(token.uses, 2)

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS,
            **{"INCORRECT_SHORT_TOKEN_REDEEMS_TOKEN": False},
        )
    )
    def test_redeeming_wrong_token_does_not_redeem_it_if_configured(self):
        token = create_token("phone_number")
        data = {"token": "bad-token", "phone_number": token.user.phone_number}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
        token.refresh_from_db()
        self.assertEqual(token.uses, 0)

    def test_redeeming_expired_token_does_not_work(self):
        past_time = timezone.now() - timedelta(
            seconds=JWT_DRF_PASSWORDLESS_settings.TOKEN_LIFETIME + 1
        )

        with mock.patch("django.utils.timezone.now", mock.Mock(return_value=past_time)):
            # Create a toke in the past
            token = create_token("phone_number")

        data = {"token": token.short_token, "phone_number": token.user.phone_number}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)
