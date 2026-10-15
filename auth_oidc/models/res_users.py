# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import hashlib
import hmac
import json
import logging

import requests

from odoo import api, models
from odoo.exceptions import AccessDenied
from odoo.http import request

_logger = logging.getLogger(__name__)

# digests of the nonces issued in the login links of the session
SESSION_NONCES_KEY = "auth_oidc_nonces"
SESSION_NONCES_MAX = 10


def nonce_digest(nonce):
    return hashlib.sha256(str(nonce).encode()).hexdigest()


def remember_nonce(session, nonce):
    """Remember a nonce issued in a login link of ``session``."""
    digests = list(session.get(SESSION_NONCES_KEY) or [])
    digests.append(nonce_digest(nonce))
    session[SESSION_NONCES_KEY] = digests[-SESSION_NONCES_MAX:]


class ResUsers(models.Model):
    _inherit = "res.users"

    def _auth_oauth_get_tokens_implicit_flow(self, oauth_provider, params):
        # https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
        return params.get("access_token"), params.get("id_token")

    def _auth_oauth_get_tokens_auth_code_flow(self, oauth_provider, params):
        # https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
        code = params.get("code")
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
        auth = None
        if oauth_provider.client_secret:
            auth = (oauth_provider.client_id, oauth_provider.client_secret)
        response = requests.post(
            oauth_provider.token_endpoint,
            data={
                "client_id": oauth_provider.client_id,
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": oauth_provider.code_verifier,  # PKCE
                "redirect_uri": request.httprequest.url_root + "auth_oauth/signin",
            },
            auth=auth,
            timeout=10,
        )
        response.raise_for_status()
        response_json = response.json()
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        return response_json.get("access_token"), response_json.get("id_token")

    @api.model
    def _auth_oidc_check_nonce(self, nonce, params):
        """Check that the id_token nonce is the one of the login state and was
        issued for the current session, then consume it. This rejects an
        id_token obtained for another login."""
        try:
            state = json.loads(params.get("state") or "{}")
        except (TypeError, ValueError):
            state = {}
        expected = state.get("n") if isinstance(state, dict) else None
        if (
            not nonce
            or not expected
            or not hmac.compare_digest(str(nonce), str(expected))
        ):
            _logger.error("id_token nonce does not match the login state.")
            raise AccessDenied()
        session = request.session if request else None
        digests = list((session or {}).get(SESSION_NONCES_KEY) or [])
        digest = nonce_digest(nonce)
        if digest not in digests:
            _logger.error("id_token nonce was not issued for this session.")
            raise AccessDenied()
        digests.remove(digest)
        session[SESSION_NONCES_KEY] = digests

    @api.model
    def auth_oauth(self, provider, params):
        oauth_provider = self.env["auth.oauth.provider"].browse(provider)
        if oauth_provider.flow == "id_token":
            access_token, id_token = self._auth_oauth_get_tokens_implicit_flow(
                oauth_provider, params
            )
        elif oauth_provider.flow == "id_token_code":
            access_token, id_token = self._auth_oauth_get_tokens_auth_code_flow(
                oauth_provider, params
            )
        else:
            return super().auth_oauth(provider, params)
        if not access_token:
            _logger.error("No access_token in response.")
            raise AccessDenied()
        if not id_token:
            _logger.error("No id_token in response.")
            raise AccessDenied()
        validation = oauth_provider._parse_id_token(id_token, access_token)
        # required check
        if "sub" in validation and "user_id" not in validation:
            # set user_id for auth_oauth, user_id is not an OpenID Connect standard
            # claim:
            # https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
            validation["user_id"] = validation["sub"]
        elif not validation.get("user_id"):
            _logger.error("user_id claim not found in id_token (after mapping).")
            raise AccessDenied()
        self._auth_oidc_check_nonce(validation.get("nonce"), params)
        # retrieve and sign in user
        params["access_token"] = access_token
        login = self._auth_oauth_signin(provider, validation, params)
        if not login:
            raise AccessDenied()
        # return user credentials
        return (self.env.cr.dbname, login, access_token)
