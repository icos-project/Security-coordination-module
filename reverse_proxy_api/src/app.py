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


from datetime import datetime
from typing import cast

import simplejson
import logging
from logging import config as log_conf
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from prance import ResolvingParser

from .api import scan, health
from .middleware import validate_keycloak

log_conf.fileConfig("logging.conf", disable_existing_loggers=False)
logging.captureWarnings(True)

APP = FastAPI()

APP.include_router(scan.router)
APP.include_router(scan.prometheus_router)
APP.include_router(health.router)

APP.middleware("http")(validate_keycloak)


def parse_wazuh_routes() -> dict:
    parser = ResolvingParser("wazuh-spec.yaml")
    spec = parser.specification

    if isinstance(spec, dict):
        paths = spec.get("paths")
        return cast(dict, paths)
    return {}


def handle_routes(paths: dict) -> dict:
    out = dict()

    key: str
    val: dict
    for key, val in paths.items():
        key = f"/wazuh{key}"

        v: dict
        for v in val.values():
            tags: list = v["tags"]
            v["tags"] = list(map(lambda x: f"Wazuh / {x}", tags))

        out[key] = val

    return out


def custom_openapi():
    if APP.openapi_schema:
        return APP.openapi_schema
    openapi_schema = get_openapi(
        title="Coordination module openapi",
        version="1.0.0",
        summary="Security Layer Coordination API is the central component of the Security Layer. It acts as a forward proxy when communicating with the Meta-Kernel Layer and the Intelligence Layer. It is implemented using FastAPI framework.",
        description="This work has received funding from the European Union's HORIZON research and innovation programme under grant agreement No. 101070177 (ICOS).",
        routes=APP.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://i.ibb.co/vsHR6f5/icos-logo.png"
    }
    existing_paths = cast(dict, openapi_schema.get("paths"))

    routes = parse_wazuh_routes()
    routes = handle_routes(routes)
    routes = simplejson.loads(
        simplejson.dumps(routes, default=datetime.isoformat, ignore_nan=True)
    )

    existing_paths.update(routes)

    APP.openapi_schema = openapi_schema
    return APP.openapi_schema


APP.openapi = custom_openapi

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(APP, host="0.0.0.0", port=8080)
