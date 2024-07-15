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


from dynaconf import Dynaconf

settings = Dynaconf(
    envvar_prefix="CONF",
    settings_files=["settings.yaml"],
    merge_enabled=True
)


class WazuhConfig:
    def wazuh_host(self) -> str:
        return settings.wazuh.host

    def wazuh_port(self) -> str:
        return settings.wazuh.port

    def wazuh_username(self) -> str:
        return settings.wazuh.auth.username

    def wazuh_password(self) -> str:
        return settings.wazuh.auth.password


WAZUH_CONFIG = WazuhConfig()

class AppConfig:
    def keycloak_rsa_public_key(self) -> str:
        return settings.keycloak.public_key

    def prometheus_metrics_disabled(self) -> bool:
        return settings.prometheus.metric_security_disabled

    def security_disabled(self) -> bool:
        return settings.security.disabled


APP_CONFIG = AppConfig()
