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


from typing import Union
from fastapi import Request
from fastapi.responses import JSONResponse

import base64
import binascii
import logging
import jwt
from src.config import APP_CONFIG


async def validate_keycloak(request: Request, call_next):
    if not should_perform_keycloak_validation(request.url.path):
        response = await call_next(request)
        return response

    logging.info('Validating keycloak')

    token_header = request.headers.get('Authorization')

    if token_header is None:
        err = 'No authorization header.'
        error = {'message': err}
        logging.warn(err)

        return JSONResponse(error, status_code=401)

    split = token_header.split(" ")

    if len(split) < 2:
        err = 'Error with the token.'
        error = {'message': err}
        logging.warn(err)

        return JSONResponse(error, status_code=401)

    token = split[1].strip()
    decoded = decode_token(token)

    if decoded is None:
        error = {'message': 'Internal server error.'}
        logging.error('Error parsing the token.')
        return JSONResponse(error, status_code=500)

    response = await call_next(request)
    return response


def should_perform_keycloak_validation(request_url: str):
    if APP_CONFIG.security_disabled():
        return False
    if request_url.startswith('/health'):
        return False
    elif request_url.startswith('/docs'):
        return False
    elif request_url.startswith('/openapi.json'):
        return False
    elif request_url.startswith('/wazuh-prometheus') and not APP_CONFIG.prometheus_metrics_disabled():
        return False
    return True


def decode_token(token: str):
    public_key = APP_CONFIG.keycloak_rsa_public_key()

    if public_key is None:
        logging.error('No keycloak public key configured.')
        return None

    public_key = '-----BEGIN PUBLIC KEY-----\n' + public_key + '\n-----END PUBLIC KEY-----'

    try:
        #TODO is the audience here correct? 
        decoded = jwt.decode(token, public_key, audience='account', algorithms=["RS256"])
        return decoded
    except Exception as e:
        logging.warn(f'Error decoding token')
        logging.warn(e)
        return None


def decode_keycloak_rsa_public_key(encoded_key: str) -> Union[bytes, None]:

    try: 
        decoded = base64.b64decode(encoded_key)
        return decoded
    except binascii.Error:
        logging.error('Cannot parse keycloak public key.')
        return None
