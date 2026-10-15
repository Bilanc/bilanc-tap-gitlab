import requests
import json
import time
from datetime import datetime, timedelta, timezone

import backoff
import singer

LOGGER = singer.get_logger()

NANGO_API_URL = "https://api.nango.dev"
NANGO_REQUEST_TIMEOUT = 30
NANGO_MAX_TRIES = 5
NANGO_MAX_RETRY_AFTER = 60
NANGO_FORCE_REFRESH_RETRY_DELAY = 5
NANGO_EXPIRES_AT_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
# The tap refreshes this long before `expires_at`; a token taken from the
# no-force fallback must outlive it or the tap would refresh again right away.
NANGO_EXPIRY_MARGIN = timedelta(minutes=20)


class NangoServerError(Exception):
    """Nango answered 429 or 5xx; retried by `fetch_nango_connection`."""


class NangoRefreshError(Exception):
    """Nango could not serve credentials for the connection."""


def nango_error_details(response):
    """Nango's `error.code: error.message`; never the connection payload."""
    try:
        error = response.json().get("error")
    except (ValueError, AttributeError):
        error = None
    if isinstance(error, dict):
        error = ": ".join(str(v) for v in (error.get("code"), error.get("message")) if v)
    if not isinstance(error, str):
        error = None
    return error or response.reason or f"HTTP {response.status_code}"


def _retry_after(response):
    try:
        return min(max(int(response.headers.get("Retry-After", 0)), 0), NANGO_MAX_RETRY_AFTER)
    except ValueError:
        return 0


@backoff.on_exception(
    backoff.expo,
    (requests.RequestException, NangoServerError),
    max_tries=NANGO_MAX_TRIES,
)
def fetch_nango_connection(session, connection_id, secret_key, provider_config_key, force_refresh):
    """GET the Nango connection, retrying timeouts, connection errors, 429 and 5xx."""
    url = f"{NANGO_API_URL}/connection/{connection_id}?provider_config_key={provider_config_key}"
    if force_refresh:
        url += "&force_refresh=true"

    response = session.get(
        url,
        headers={"Authorization": f"Bearer {secret_key}"},
        timeout=NANGO_REQUEST_TIMEOUT,
    )

    if response.status_code == 429:
        time.sleep(_retry_after(response))
    if response.status_code == 429 or response.status_code >= 500:
        raise NangoServerError(
            f"Nango returned {response.status_code}: {nango_error_details(response)}"
        )
    return response


def parse_nango_expires_at(expires_at_str):
    return datetime.strptime(expires_at_str, NANGO_EXPIRES_AT_FORMAT).replace(tzinfo=timezone.utc)


def _outlives_margin(expires_at_str):
    try:
        expiry = parse_nango_expires_at(expires_at_str)
    except (TypeError, ValueError):
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

            # A 400 on the forced refresh (GitLab rejected that one refresh) is
            # retried once without force_refresh; the token Nango still holds
            # is used if it outlives NANGO_EXPIRY_MARGIN.
            response = fetch_nango_connection(
                self.__session, self.__nango_connection_id, self.__nango_secret_key,
                provider_key, force_refresh=True)

            forced_refresh_error = None
            if response.status_code == 400:
                forced_refresh_error = nango_error_details(response)
                LOGGER.warning(
                    "Nango force_refresh failed (%s); retrying without force_refresh",
                    forced_refresh_error,
                )
                time.sleep(NANGO_FORCE_REFRESH_RETRY_DELAY)
                response = fetch_nango_connection(
                    self.__session, self.__nango_connection_id, self.__nango_secret_key,
                    provider_key, force_refresh=False)

            if not response.ok:
                raise NangoRefreshError(
                    f"Nango returned {response.status_code} for connection "
                    f"{self.__nango_connection_id}: {nango_error_details(response)}"
                )

            credentials = response.json().get("credentials", {})

            if self.__self_hosted:
                self.__access_token = credentials.get("apiKey")
                self.__expires_at = datetime.max.replace(tzinfo=timezone.utc)
                return

            expires_at_str = credentials.get("expires_at")
            if forced_refresh_error and not _outlives_margin(expires_at_str):
                raise NangoRefreshError(
                    f"Nango returned 400 on force_refresh for connection "
                    f"{self.__nango_connection_id}: {forced_refresh_error}; the token "
                    f"Nango still holds expires at {expires_at_str}, too soon to use"
                )
            self.__access_token = credentials.get("access_token")
            self.__expires_at = parse_nango_expires_at(expires_at_str) - NANGO_EXPIRY_MARGIN

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
