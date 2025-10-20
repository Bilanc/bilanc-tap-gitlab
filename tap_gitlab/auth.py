import requests
import json
from datetime import datetime, timedelta, timezone

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

            url = f"https://api.nango.dev/connection/{self.__nango_connection_id}?provider_config_key=gitlab&force_refresh=true"

            response = self.__session.get(
                url,
                headers={
                    "Authorization": f"Bearer {self.__nango_secret_key}",
                    "Content-Type": "application/json",
                },
            )

            if response.status_code != 200:
                raise Exception(response.text)

            data = response.json()

            self.__access_token = data.get("credentials", {}).get("access_token")
            expires_at_str = data.get("credentials", {}).get("expires_at")
            self.__expires_at = datetime.strptime(expires_at_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc) - timedelta(minutes=20)

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
