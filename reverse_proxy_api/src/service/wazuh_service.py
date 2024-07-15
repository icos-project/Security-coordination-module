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


from dataclasses import dataclass
from typing import List

from src.models.request_models import Method, ResponseError
from src.wazuh import client_singleton
from src.models import Result


@dataclass
class Agent:
    id: str
    name: str
    ip: str
    uname: str
    hostname: str


@dataclass
class AgentVulnerability:
    agent_id: str
    agent_name: str
    ip: str
    agent_uname: str
    agent_hostname: str
    severity: str


def get_hostname_from_uname(uname: str):
    hostname = uname.split("|")[1]
    return hostname.strip()


def create_agent_from_res(agent):
    uname = agent["os"]["uname"]
    hostname = get_hostname_from_uname(uname)

    return Agent(agent["id"], agent["name"], agent["ip"], uname, hostname)


def get_agent_ids() -> Result[List[Agent], ResponseError]:
    request_url = "/agents"
    qp = {"select": ["id", "name", "ip", "os.uname"]}

    r = client_singleton.request(Method.GET, request_url, query_params=qp)

    return r.map_item(lambda x: x["data"]["affected_items"]).map_item(
        lambda agents: list(map(create_agent_from_res, agents))
    )


def get_active_agent_vulnerabilities(agent: Agent) -> Result[List[AgentVulnerability], ResponseError]:
    request_url = f"/vulnerability/{agent.id}"
    qp = {"status": "valid"}

    r = client_singleton.request(Method.GET, request_url, query_params=qp)

    vuln_map_fn = lambda x: AgentVulnerability(
        agent.id, agent.name, agent.ip, agent.uname, agent.hostname, x["severity"]
    )
    return r.map_item(lambda x: x["data"]["affected_items"]).map_item(lambda vulnerabilities: list(map(vuln_map_fn, vulnerabilities)))


def get_active_vulnerabilities_for_agents(agents: List[Agent]) -> Result[List[AgentVulnerability], ResponseError]:
    vulnerabilities: List[AgentVulnerability] = []
    for agent in agents:
        # TODO this is blocking, for many agents, this will probably take a long time
        r = get_active_agent_vulnerabilities(agent)

        if r.has_error():
            return Result(None, r.err)

        vuln = r.unwrap()

        vulnerabilities.extend(vuln)

    return Result(vulnerabilities, None)


def get_sca_score_for_agent(agent: Agent):
    request_url = f"/sca/{agent.id}"

    r = client_singleton.request(Method.GET, request_url)
    return r.map_item(lambda x: x["data"]["affected_items"][0]["score"])
