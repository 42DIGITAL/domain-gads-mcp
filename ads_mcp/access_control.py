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

"""Restricts which Google accounts may use the server over the OAuth proxy.

Google OAuth alone lets any Google account sign in. When the server is hosted
publicly (for example on Cloud Run with unauthenticated ingress, which MCP
clients require for OAuth discovery), this module limits access to accounts
whose verified email belongs to an allowed domain or is explicitly listed.
"""

import dataclasses
import logging
import os
from typing import Any

from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.providers.google import GoogleProvider

logger = logging.getLogger(__name__)

ALLOWED_DOMAINS_ENV_VAR = "GOOGLE_ADS_MCP_ALLOWED_DOMAINS"
ALLOWED_EMAILS_ENV_VAR = "GOOGLE_ADS_MCP_ALLOWED_EMAILS"


def _parse_list(value: str | None) -> frozenset[str]:
    """Parses a comma-separated env value into lowercase, non-empty entries."""
    if not value:
        return frozenset()
    return frozenset(
        item.strip().lower() for item in value.split(",") if item.strip()
    )


def _is_verified(value: Any) -> bool:
    """Google's tokeninfo returns "true" as a string; userinfo returns a bool."""
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() == "true"


@dataclasses.dataclass(frozen=True)
class AccessPolicy:
    """Allows an account whose email is in a listed domain OR is listed itself."""

    domains: frozenset[str] = frozenset()
    emails: frozenset[str] = frozenset()

    @classmethod
    def from_env(cls) -> "AccessPolicy":
        domains = frozenset(
            d.lstrip("@")
            for d in _parse_list(os.environ.get(ALLOWED_DOMAINS_ENV_VAR))
        )
        emails = _parse_list(os.environ.get(ALLOWED_EMAILS_ENV_VAR))
        return cls(domains=domains, emails=emails)

    @property
    def enabled(self) -> bool:
        return bool(self.domains or self.emails)

    def is_allowed(self, claims: dict[str, Any]) -> bool:
        """Returns True if the verified email in `claims` satisfies the policy.

        The domain is taken from the verified email address rather than
        Google's `hd` claim, because `hd` is only present for Google Workspace
        accounts and domain users may sign in with a consumer Google account.
        """
        email = (claims.get("email") or "").strip().lower()
        if not email or not _is_verified(claims.get("email_verified")):
            return False
        if email in self.emails:
            return True
        _, _, domain = email.rpartition("@")
        return bool(domain) and domain in self.domains


class RestrictedGoogleProvider(GoogleProvider):
    """GoogleProvider that rejects tokens of accounts outside the policy.

    FastMCP validates the upstream Google token on every request through
    `load_access_token`, so returning None here yields HTTP 401 before any
    tool or resource runs.
    """

    def __init__(self, *, access_policy: AccessPolicy, **kwargs: Any):
        super().__init__(**kwargs)
        self._access_policy = access_policy

    async def load_access_token(self, token: str) -> AccessToken | None:
        access_token = await super().load_access_token(token)
        if access_token is None:
            return None
        claims = access_token.claims or {}
        if not self._access_policy.is_allowed(claims):
            logger.warning(
                "Denied access for Google account %r (email_verified=%r).",
                claims.get("email"),
                claims.get("email_verified"),
            )
            return None
        return access_token
