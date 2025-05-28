# SpiderSim - A Network Attack Simulation Environment
# Copyright (c) 2024 NRT

# This project includes code modified from CyberBattle 
# (https://github.com/microsoft/CyberBattleSim/tree/main/cyberbattle) used under Licensed under the MIT License.


"""A tiny toy environment"""

from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple

default_allow_rules = [
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
]

# Network nodes involved in the Capture the flag game
nodes = {
    "Website": m.NodeInfo(
        services=[m.ListeningService("SSH", allowedCredentials=["ReusedMySqlCred-web"])],
        firewall=m.FirewallConfiguration(incoming=default_allow_rules, outgoing=default_allow_rules + [m.FirewallRule("su", m.RulePermission.ALLOW), m.FirewallRule("sudo", m.RulePermission.ALLOW)]),
        value=1000,
        properties=["MySql", "Ubuntu", "nginx/1.10.3"],
        owned_string="FLAG: Login using insecure SSH user/password",
        vulnerabilities=dict(
            ScanPageSource=m.VulnerabilityInfo(
                description="Website page source contains refrence to browseable " "relative web directory",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["Website.Directory"]),
                reward_string="Viewing the web page source reveals a URL to a .txt file and directory on the website",
                cost=1.0,
            ),
        ),
    ),
    "Website.Directory": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],
        value=50,
        properties=["Ubuntu", "nginx/1.10.3", "CTFFLAG:Readme.txt-Discover secret data"],
        vulnerabilities=dict(
            NavigateWebDirectoryFurther=m.VulnerabilityInfo(
                description="Discover MYSQL credentials MySql for user " "'web' in (getting-started.txt)",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="Website", port="MySQL", credential="ReusedMySqlCred-web")]),
                reward_string="Discover browseable web directory: Navigating to parent URL revealed file `readme.txt`" "with secret data (aflag); and `getting-started.txt` with MYSQL credentials",
                cost=1.0,
            ),
        ),
    ),
    "client": m.NodeInfo(
        services=[],
        properties=["CLIENT:Win10"],
        value=0,
        vulnerabilities=dict(
            SearchComputeServer = m.VulnerabilityInfo(
                description="Search ComputeServer for list of accessed servers",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="ComputeServer", port="SSH",
                         credential="ServerCredential")]),
                reward_string="Find the entrance to the ComputeServer",
                cost=1.0
            )),
        agent_installed=True,
        reimagable=False,
    ),
    'ComputeServer': m.NodeInfo(
        services=[m.ListeningService("SSH", allowedCredentials=["ServerCredential"])],
        value=1000,
        properties=["Linux", "ComputeNode", "GPU"],
        vulnerabilities=dict(
            MiningVuln=m.VulnerabilityInfo(
                description="一个允许劫持算力资源的漏洞",
                type=m.VulnerabilityType.COMPUTATION_LEAK,
                precondition=m.Precondition('ComputeNode&GPU'),
                outcome=m.ComputationResourcesLeaked(
                    computation_resources=["gpu", "cpu"],
                    amount=10.0
                ),
                reward_string="成功劫持计算资源",
                cost=2.0,
            )
        )
    ),
}

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])


# Environment constants
ENV_IDENTIFIERS = m.infer_constants_from_nodes(cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())), global_vulnerability_library)


def new_environment() -> m.Environment:
    network_state = m.NetworkState()
    network_state.computation_resources = {
        "gpu": m.ComputationResource(
            id="gpu", 
            total_amount=100.0, 
            current_amount=100.0, 
            value_per_unit=0.5
        ),
        "cpu": m.ComputationResource(
            id="cpu", 
            total_amount=200.0, 
            current_amount=200.0, 
            value_per_unit=0.2
        )
    }
    network_state.hijacked_computation = {}
    
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS,
        network_state=network_state
    )