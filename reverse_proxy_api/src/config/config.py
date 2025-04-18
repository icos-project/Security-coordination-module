#  Reverse proxy api
#  Copyright © 2022-2024 ICOS Consortium
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  This work has received funding from the European Union's HORIZON research
#  and innovation programme under grant agreement No. 101070177.


import os

class WazuhConfig:
    def wazuh_host(self) -> str:
        return os.getenv("WAZUH_HOST")

    def wazuh_port(self) -> str:
        return os.getenv("WAZUH_PORT")

    def wazuh_username(self) -> str:
        return os.getenv("WAZUH_USERNAME")

    def wazuh_password(self) -> str:
        return os.getenv("WAZUH_PASSWORD")


WAZUH_CONFIG = WazuhConfig()

class AppConfig:

    def prometheus_metrics_disabled(self) -> bool:
        return os.getenv("PROMETHEUS_METRICS_DISABLED")

    def security_disabled(self) -> bool:
        return os.getenv("SECURITY_DISABLED")


APP_CONFIG = AppConfig()

class KeycloakConfig:

    def server_url(self) -> str:
        return os.getenv("KEYCLOAK_SERVER_URL")

    def realm_name(self) -> str:
        return os.getenv("KEYCLOAK_REALM_NAME")

    def resource_server_id(self) -> str:
        return os.getenv("KEYCLOAK_RESOURCE_SERVER_ID")

    def audience(self) -> str:
        return os.getenv("KEYCLOAK_AUDIENCE")

    def client_id(self) -> str:
        return os.getenv("KEYCLOAK_CLIENT_ID")

    def client_secret_key(self) -> str:
        return os.getenv("KEYCLOAK_CLIENT_SECRET_KEY")

KEYCLOAK_CONFIG = KeycloakConfig()
