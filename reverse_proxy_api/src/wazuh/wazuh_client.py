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


import logging
from typing import Any, Union, assert_never

import requests
from requests.auth import HTTPBasicAuth
from src.models import Result
from src.config import config
from src.models.request_models import Method, ResponseError


wazuh_username = config.WAZUH_CONFIG.wazuh_username()
wazuh_password = config.WAZUH_CONFIG.wazuh_password()

basic_auth = HTTPBasicAuth(wazuh_username, wazuh_password)

wazuh_host = config.WAZUH_CONFIG.wazuh_host()
wazuh_port = config.WAZUH_CONFIG.wazuh_port()

wazuh_base_url = f"https://{wazuh_host}:{wazuh_port}/"

logger = logging.getLogger(__name__)


class WazuhClient:
    def __init__(self) -> None:
        self.jwt_token: Union[None, str] = None

    def _request_jwt_token(self):
        auth_url = "/security/user/authenticate"
        url = self._get_url(auth_url)

        r = requests.post(url, auth=basic_auth, verify=False)

        response = r.json()

        if "data" in response and "token" in response["data"]:
            token = response["data"]["token"]

            self.jwt_token = token
        else:
            logger.error("Error getting token: ")
            logger.error(response)
            token = None

    def _get_url(self, request_url: str) -> str:
        if request_url.startswith("/"):
            request_url = request_url[1:]

        return f"{wazuh_base_url}{request_url}"

    def request_response(
        self, method: Method, request_url: str, body=None, query_params=None
    ) -> requests.Response:

        if self.jwt_token is None:
            self._request_jwt_token()

        result = self._make_request(method, request_url, body, query_params)
        if result.status_code == 401:
            self._request_jwt_token()
            result = self._make_request(method, request_url, body, query_params)

        return result

    def request(self, method: Method, request_url: str, body=None, query_params=None) -> Result[Any, ResponseError]:
        response = self.request_response(method, request_url, body, query_params)

        if response.status_code > 200:
            logger.error("Error getting response from Wazuh")
            logger.error(response)
            r = response.json()

            return Result(None, ResponseError(response.status_code, r["title"], r["detail"]))

        return Result(response.json(), None)

    def _make_request(self, method: Method, request_url: str, body=None, query_params=None) -> requests.Response:
        url = self._get_url(request_url)

        head: Any = {"Authorization": f"Bearer {self.jwt_token}"}
        param = {
            "headers": head,
            "data": body,
            "verify": False,
            "params": query_params,
            "timeout": 60,
        }

        match method:
            case Method.GET:
                return requests.get(url, **param)
            case Method.PUT:
                return requests.put(url, **param)
            case Method.POST:
                return requests.post(url, **param)
            case Method.DELETE:
                return requests.delete(url, **param)
            case _:
                assert_never(method)
