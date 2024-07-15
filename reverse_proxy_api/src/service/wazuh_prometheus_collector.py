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


from collections import defaultdict
from typing import Dict, Iterable
import logging

from src.models import Result

from prometheus_client import Metric
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector, CollectorRegistry

from .wazuh_service import (
    get_active_vulnerabilities_for_agents,
    get_agent_ids,
    get_sca_score_for_agent,
)

logger = logging.getLogger(__name__)


def _create_vulnerability_metric():
    c = GaugeMetricFamily(
        "vulnerabilities",
        "Agregated information about the vulnerabilities",
        labels=[
            "agent_name",
            "agent_ip",
            "agent_uname",
            "agent_hostname",
            "severity",
        ],
    )

    agent_r = get_agent_ids()

    if agent_r.has_error():
        return Result(None, agent_r.err)

    agents = agent_r.unwrap()

    r = get_active_vulnerabilities_for_agents(agents)

    if r.has_error():
        return

    vulns = r.unwrap()
    vuln_counts: Dict[str, defaultdict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )

    for vuln in vulns:
        agent_name = vuln.agent_name
        vuln_level = vuln.severity

        vuln_counts[agent_name][vuln_level] += 1

    for agent in agents:
        agent_vulnerabilities = vuln_counts[agent.name]

        for level, count in agent_vulnerabilities.items():
            c.add_metric(
                [agent.name, agent.ip, agent.uname, agent.hostname, level], count
            )
    return c


def _create_sca_metric():

    c = GaugeMetricFamily(
        "SCA_score",
        "SCA score of the agent",
        labels=["agent_name", "agent_ip", "agent_uname", "agent_hostname"],
    )

    agent_r = get_agent_ids()

    if agent_r.has_error():
        return Result(None, agent_r.err)

    agents = agent_r.unwrap()

    for agent in agents:
        sca_score = get_sca_score_for_agent(agent).unwrap()
        c.add_metric([agent.name, agent.ip, agent.uname, agent.hostname], sca_score)

    return c


class WazuhCollector(Collector):
    def collect(self) -> Iterable[Metric]:
        logger.info("Triggered metric collection")

        yield _create_vulnerability_metric()
        yield _create_sca_metric()

        logger.info("Finished metric collection")


collector = WazuhCollector()

wazuh_registry = CollectorRegistry()
wazuh_registry.register(collector)
