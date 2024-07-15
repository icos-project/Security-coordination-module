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

from typing import cast
from fastapi import APIRouter, Request, Response
from fastapi.responses import PlainTextResponse
from prometheus_client import generate_latest
from src.service.wazuh_prometheus_collector import wazuh_registry
from src.wazuh import client_singleton
from src.models.request_models import Method, ResponseError

router = APIRouter(prefix="/wazuh")

@router.get("/{rest_of_path:path}", include_in_schema=False)
def wazuh_get(request: Request, response: Response, rest_of_path: str):
    r = client_singleton.request(Method.GET, rest_of_path, query_params=request.query_params)

    if r.has_error():
        err = cast(ResponseError, r.err)

        response.status_code = err.status_code
        return err.get_error_object()
        
    return r.item


@router.post("/{rest_of_path:path}", include_in_schema=False)
def wazuh_post(request: Request, response: Response, rest_of_path: str):
    r = client_singleton.request(Method.POST, rest_of_path, query_params=request.query_params)
    
    if r.has_error():
        err = cast(ResponseError, r.err)

        response.status_code = err.status_code
        return err.get_error_object()
        
    return r.item


@router.put("/{rest_of_path:path}", include_in_schema=False)
def wazuh_put(request: Request, response: Response, rest_of_path: str):
    r = client_singleton.request(Method.PUT, rest_of_path, query_params=request.query_params)
    
    if r.has_error():
        err = cast(ResponseError, r.err)

        response.status_code = err.status_code
        return err.get_error_object()
        
    return r.item


@router.delete("/{rest_of_path:path}", include_in_schema=False)
def wazuh_delete(request: Request, response: Response, rest_of_path: str):
    r = client_singleton.request(Method.DELETE, rest_of_path, query_params=request.query_params)
    
    if r.has_error():
        err = cast(ResponseError, r.err)

        response.status_code = err.status_code
        return err.get_error_object()
        
    return r.item

prometheus_router = APIRouter(prefix="/wazuh-prometheus")


@prometheus_router.get("/metrics", response_class=PlainTextResponse)
def get_all_metrics():
    return generate_latest(wazuh_registry)
