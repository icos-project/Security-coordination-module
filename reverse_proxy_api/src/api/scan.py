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
from fastapi.responses import PlainTextResponse, JSONResponse
from prometheus_client import generate_latest
from src.service.wazuh_prometheus_collector import wazuh_registry, basic_score
from src.wazuh import client_singleton
from src.models.request_models import Method, ResponseError
from pydantic import BaseModel
from src.service.wazuh_service import get_manually_defined_scores, set_manually_defined_scores

class Item(BaseModel):
    agent_id: str
    score: int
    node_name: str

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

def get_agent_scores():
    scores = get_manually_defined_scores()
    if not scores:
        scores["agents"] = list()
        r = client_singleton.request(Method.GET, "/agents")
        for agent in r.item["data"]["affected_items"]:
            rspns = client_singleton.request(Method.GET, f"/sca/{agent['id']}")
            rspns.item["data"]["agent_id"] = agent["id"]
            rspns.item["data"]["node_name"] = agent["node_name"]
            scores["agents"].append(rspns.item["data"])

prometheus_router = APIRouter(prefix="/wazuh-prometheus")
@prometheus_router.get("/metrics", response_class=PlainTextResponse)
def get_all_metrics(request: Request, response: Response):
    return generate_latest(wazuh_registry)

def manually_change_sca(item: Item):
    agent_score_dict = get_manually_defined_scores()
    for agent in agent_score_dict["agents"]:
        if item.agent_id == agent["agent_id"]:
            agent["affected_items"][0]["score"] = item.score

router_sca = APIRouter(prefix="/sca")
@router_sca.post("/chage")
async def create_item(item: Item):
    get_agent_scores()
    manually_change_sca(item)
    return get_manually_defined_scores()
