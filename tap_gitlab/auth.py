import requests
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import backoff
import singer

LOGGER = singer.get_logger()

NANGO_API_URL = "https://api.nango.dev"
NANGO_REQUEST_TIMEOUT = 30
NANGO_MAX_TRIES = 5
NANGO_FORCE_REFRESH_RETRY_DELAY = 5
NANGO_MAX_RETRY_AFTER = 60
NANGO_EXPIRES_AT_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
# The tap treats a Nango access token as stale this long before `expires_at`
# (Nango itself refreshes within 15 minutes of expiry). A token handed back by
# the no-force fallback must outlive this margin, otherwise every GitLab
# request would re-run the failing forced refresh.
NANGO_EXPIRY_MARGIN = timedelta(minutes=20)


class NangoServerError(Exception):
    """Nango answered with a 429 or 5xx; retried by `fetch_nango_connection`."""

    def __init__(self, message, retry_after=0):
        super().__init__(message)
        self.retry_after = retry_after


class NangoRefreshError(Exception):
    """Nango could not serve credentials for the connection (non-retriable)."""

    def __init__(self, message, response=None):
        super().__init__(message)
        self.response = response
        self.status_code = response.status_code if response is not None else None


def nango_error_details(response):
    """Return Nango's `error.code: error.message` from an error body.

    Only the error fields are surfaced so alerts never carry the connection
    payload (end user name/email, credentials).
    """
    try:
        body = response.json()
    except ValueError:
        body = None

    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict):
        code = error.get("code") or error.get("type")
        message = error.get("message")
        details = ": ".join(str(part) for part in (code, message) if part)
        if details:
            return details
    if isinstance(error, str) and error:
        return error

    return (response.reason or "").strip() or f"HTTP {response.status_code}"


def retry_after_seconds(response):
    """Seconds Nango asked us to wait (`Retry-After`, delay or HTTP-date), capped."""
    header = response.headers.get("Retry-After")
    if not header:
        return 0
    try:
        seconds = int(header)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(header)
        except (TypeError, ValueError):
            return 0
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        seconds = (retry_at - datetime.now(timezone.utc)).total_seconds()
    return min(max(seconds, 0), NANGO_MAX_RETRY_AFTER)


def _wait_for_retry_after(details):
    """backoff hook: top the backoff delay up to Nango's `Retry-After`.

    Runs only when another attempt follows, so an exhausted retry budget
    fails immediately instead of sleeping first.
    """
    error = sys.exc_info()[1]
    extra = getattr(error, "retry_after", 0) - details.get("wait", 0)
    if extra > 0:
        time.sleep(extra)


@backoff.on_exception(
    backoff.expo,
    (
        requests.Timeout,
        requests.ConnectionError,
        requests.exceptions.ChunkedEncodingError,
        NangoServerError,
    ),
    max_tries=NANGO_MAX_TRIES,
    factor=2,
    on_backoff=_wait_for_retry_after,
)
def fetch_nango_connection(session, connection_id, secret_key, provider_config_key, force_refresh):
    """GET the Nango connection, retrying timeouts, connection errors, 429 and 5xx."""
    url = f"{NANGO_API_URL}/connection/{connection_id}?provider_config_key={provider_config_key}"
    if force_refresh:
        url += "&force_refresh=true"

    response = session.get(
        url,
        headers={
            "Authorization": f"Bearer {secret_key}",
            "Content-Type": "application/json",
        },
        timeout=NANGO_REQUEST_TIMEOUT,
    )

    if response.status_code == 429 or response.status_code >= 500:
        raise NangoServerError(
            f"Nango returned {response.status_code} fetching connection "
            f"(force_refresh={force_refresh}): {nango_error_details(response)}",
            retry_after=retry_after_seconds(response),
        )

    return response


def parse_nango_expires_at(expires_at_str):
    return datetime.strptime(expires_at_str, NANGO_EXPIRES_AT_FORMAT).replace(tzinfo=timezone.utc)


def _outlives_margin(expires_at_str):
    """True if the token is usable for longer than `NANGO_EXPIRY_MARGIN`."""
    if not expires_at_str:
        return False
    try:
        expiry = parse_nango_expires_at(expires_at_str)
    except ValueError:
        return False
    return expiry - NANGO_EXPIRY_MARGIN > datetime.now(timezone.utc)


class GitlabAuth:
    def __init__(self, config_path):
        self.__config_path = config_path
        self.__config = self.read_config()
        self.__redirect_uri = self.__config.get("redirect_uri")
        self.__client_id = self.__config.get("client_id")
        self.__client_secret = self.__config.get("client_secret")
        self.__refresh_token = self.__config.get("refresh_token")
        self.__private_token = self.__config.get("private_token")
        self.__nango_connection_id = self.__config.get("nango_connection_id")
        self.__nango_secret_key = self.__config.get("nango_secret_key")
        self.__self_hosted = self.__config.get("self_hosted", False)
        if isinstance(self.__private_token, str):
            self.__private_token = self.__private_token.strip()


        if not self.__private_token and \
            (not self.__client_id
                or not self.__client_secret
                or not self.__redirect_uri
                or not self.__refresh_token) \
            and (not self.__nango_connection_id or not self.__nango_secret_key):
            raise Exception("private_token or client_id, client_secret, redirect_uri, and refresh_token are required")

        self.__session = requests.Session()
        self.__access_token = None
        self.__expires_at = None

    def read_config(self):
        with open(self.__config_path, "r") as config_file:
            return json.load(config_file)

    def save_config(self):
        with open(self.__config_path, "w") as outfile:
            json.dump(self.__config, outfile, indent=4)

    def oauth_2_ensure_access_token(self):
        if self.__access_token is None or self.__expires_at <= datetime.now(timezone.utc):
            response = self.__session.post(
                "https://gitlab.com/oauth/token",
                data={
                    "client_id": self.__client_id,
                    "client_secret": self.__client_secret,
                    "redirect_uri": self.__redirect_uri,
                    "refresh_token": self.__refresh_token,
                    "grant_type": "refresh_token"
                },
            )

            if response.status_code != 200:
                raise Exception(response.text)

            data = response.json()

            self.__access_token = data["access_token"]
            self.__config["refresh_token"] = data["refresh_token"]
            self.__config["access_token"] = data["access_token"]

            self.save_config()

            self.__expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=int(data["expires_in"]) - 10
            )

    def nango_ensure_access_token(self):
        if self.__access_token is None or self.__expires_at <= datetime.now(timezone.utc):
            if not self.__nango_secret_key or not self.__nango_connection_id:
                raise Exception("nango_secret_key and nango_connection_id are required for Nango authentication")
            
            provider_key: str = "gitlab-pat" if self.__self_hosted else "gitlab"

            # Timeouts, connection errors and Nango 5xx are backed off and
            # retried. A 400 on the forced refresh (GitLab rejected this one
            # refresh) is retried once without force_refresh since Nango still
            # holds a valid token; that token is only accepted if it outlives
            # NANGO_EXPIRY_MARGIN so we do not re-run the failing refresh on
            # every request. Anything else non-2xx raises NangoRefreshError
            # with Nango's error code/message only (never the connection
            # payload, which carries the end user's name and email).
            response = fetch_nango_connection(
                self.__session, self.__nango_connection_id, self.__nango_secret_key,
                provider_key, force_refresh=True)

            forced_refresh_response = None
            forced_refresh_error = None
            if response.status_code == 400:
                forced_refresh_response = response
                forced_refresh_error = nango_error_details(response)
                LOGGER.warning(
                    "Nango returned 400 on force_refresh of connection (%s); retrying in "
                    "%ss without force_refresh",
                    forced_refresh_error,
                    NANGO_FORCE_REFRESH_RETRY_DELAY,
                )
                time.sleep(NANGO_FORCE_REFRESH_RETRY_DELAY)
                response = fetch_nango_connection(
                    self.__session, self.__nango_connection_id, self.__nango_secret_key,
                    provider_key, force_refresh=False)

            if not response.ok:
                raise NangoRefreshError(
                    f"Nango returned {response.status_code} for connection "
                    f"{self.__nango_connection_id} ({provider_key}): "
                    f"{nango_error_details(response)}",
                    response,
                )

            credentials = response.json().get("credentials", {})

            if not self.__self_hosted:
                expires_at_str = credentials.get("expires_at")
                if forced_refresh_error is not None and not _outlives_margin(expires_at_str):
                    raise NangoRefreshError(
                        f"Nango returned 400 on force_refresh for connection "
                        f"{self.__nango_connection_id} ({provider_key}): "
                        f"{forced_refresh_error}; the token Nango still holds expires at "
                        f"{expires_at_str}, too soon to use",
                        forced_refresh_response,
                    )
                self.__access_token = credentials.get("access_token")
                self.__expires_at = parse_nango_expires_at(expires_at_str) - NANGO_EXPIRY_MARGIN
            else:
                self.__access_token = credentials.get("apiKey")
                self.__expires_at = datetime.max.replace(tzinfo=timezone.utc)

    def get_auth_token(self):
        if self.__private_token:
            token = self.__private_token
        elif self.__nango_secret_key and self.__nango_connection_id:
            self.nango_ensure_access_token()
            token = self.__access_token
        else:
            self.oauth_2_ensure_access_token()
            token = self.__access_token

        return token
