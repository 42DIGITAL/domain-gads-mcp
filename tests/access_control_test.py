# Copyright 2026 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for the domain and email access policy."""

import asyncio
import os
import unittest
from unittest.mock import AsyncMock, patch

from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.providers.google import GoogleProvider

from ads_mcp.access_control import (
    ALLOWED_DOMAINS_ENV_VAR,
    ALLOWED_EMAILS_ENV_VAR,
    AccessPolicy,
    RestrictedGoogleProvider,
)


def _claims(email, verified=True):
    return {"email": email, "email_verified": verified}


class TestAccessPolicy(unittest.TestCase):
    """Tests AccessPolicy parsing and matching."""

    def setUp(self):
        self.orig_env = {}
        for key in (ALLOWED_DOMAINS_ENV_VAR, ALLOWED_EMAILS_ENV_VAR):
            if key in os.environ:
                self.orig_env[key] = os.environ.pop(key)

    def tearDown(self):
        for key in (ALLOWED_DOMAINS_ENV_VAR, ALLOWED_EMAILS_ENV_VAR):
            os.environ.pop(key, None)
        os.environ.update(self.orig_env)

    def test_from_env_unset_is_disabled(self):
        self.assertFalse(AccessPolicy.from_env().enabled)

    def test_from_env_blank_entries_are_disabled(self):
        os.environ[ALLOWED_DOMAINS_ENV_VAR] = " , ,"
        os.environ[ALLOWED_EMAILS_ENV_VAR] = ""
        self.assertFalse(AccessPolicy.from_env().enabled)

    def test_from_env_normalizes_entries(self):
        os.environ[ALLOWED_DOMAINS_ENV_VAR] = " Example.COM, @other.org "
        os.environ[ALLOWED_EMAILS_ENV_VAR] = "Guest@Partner.com ,"
        policy = AccessPolicy.from_env()
        self.assertEqual(policy.domains, {"example.com", "other.org"})
        self.assertEqual(policy.emails, {"guest@partner.com"})
        self.assertTrue(policy.enabled)

    def test_domain_match_allowed(self):
        policy = AccessPolicy(domains=frozenset({"example.com"}))
        self.assertTrue(policy.is_allowed(_claims("Alice@Example.com")))

    def test_listed_email_allowed_outside_domain(self):
        policy = AccessPolicy(
            domains=frozenset({"example.com"}),
            emails=frozenset({"guest@partner.com"}),
        )
        self.assertTrue(policy.is_allowed(_claims("guest@partner.com")))

    def test_unlisted_email_outside_domain_denied(self):
        policy = AccessPolicy(
            domains=frozenset({"example.com"}),
            emails=frozenset({"guest@partner.com"}),
        )
        self.assertFalse(policy.is_allowed(_claims("other@partner.com")))

    def test_emails_only_policy_denies_others(self):
        policy = AccessPolicy(emails=frozenset({"alice@example.com"}))
        self.assertTrue(policy.is_allowed(_claims("alice@example.com")))
        self.assertFalse(policy.is_allowed(_claims("bob@example.com")))

    def test_subdomain_and_lookalike_denied(self):
        policy = AccessPolicy(domains=frozenset({"example.com"}))
        self.assertFalse(policy.is_allowed(_claims("a@sub.example.com")))
        self.assertFalse(policy.is_allowed(_claims("a@evilexample.com")))
        self.assertFalse(policy.is_allowed(_claims("example.com@evil.com")))

    def test_unverified_email_denied(self):
        policy = AccessPolicy(
            domains=frozenset({"example.com"}),
            emails=frozenset({"guest@partner.com"}),
        )
        self.assertFalse(policy.is_allowed(_claims("a@example.com", False)))
        self.assertFalse(policy.is_allowed(_claims("guest@partner.com", None)))
        self.assertFalse(policy.is_allowed(_claims("a@example.com", "false")))

    def test_string_verified_flag_accepted(self):
        policy = AccessPolicy(domains=frozenset({"example.com"}))
        self.assertTrue(policy.is_allowed(_claims("a@example.com", "true")))

    def test_missing_email_denied(self):
        policy = AccessPolicy(domains=frozenset({"example.com"}))
        self.assertFalse(policy.is_allowed({"email_verified": True}))
        self.assertFalse(policy.is_allowed({}))


class TestRestrictedGoogleProvider(unittest.TestCase):
    """Tests that the provider filters tokens validated by GoogleProvider."""

    def setUp(self):
        self.provider = RestrictedGoogleProvider(
            access_policy=AccessPolicy(
                domains=frozenset({"example.com"}),
                emails=frozenset({"guest@partner.com"}),
            ),
            client_id="client-id",
            client_secret="client-secret",
            base_url="http://localhost:8080",
            jwt_signing_key="test-signing-key",
        )

    def _load(self, upstream_result):
        with patch.object(
            GoogleProvider,
            "load_access_token",
            new=AsyncMock(return_value=upstream_result),
        ):
            return asyncio.run(self.provider.load_access_token("jwt"))

    def _token(self, claims):
        return AccessToken(
            token="upstream", client_id="sub", scopes=[], claims=claims
        )

    def test_allowed_domain_token_passes(self):
        token = self._token(_claims("alice@example.com"))
        self.assertIs(self._load(token), token)

    def test_allowed_listed_email_token_passes(self):
        token = self._token(_claims("guest@partner.com"))
        self.assertIs(self._load(token), token)

    def test_disallowed_token_rejected(self):
        self.assertIsNone(self._load(self._token(_claims("x@gmail.com"))))

    def test_invalid_upstream_token_stays_rejected(self):
        self.assertIsNone(self._load(None))

    def test_verify_token_enforces_policy(self):
        """Bearer auth calls verify_token, which must route through the check."""
        with patch.object(
            GoogleProvider,
            "load_access_token",
            new=AsyncMock(return_value=self._token(_claims("x@gmail.com"))),
        ):
            self.assertIsNone(asyncio.run(self.provider.verify_token("jwt")))


if __name__ == "__main__":
    unittest.main()
