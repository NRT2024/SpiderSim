from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple

default_allow_rules = [
    m.FirewallRule("RDP", m.RulePermission.ALLOW),
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
    m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
    m.FirewallRule("HTTP", m.RulePermission.ALLOW),
    m.FirewallRule("SMB", m.RulePermission.ALLOW)
]


nodes = {
    "Initial_agent_nede": m.NodeInfo(
        services=[m.ListeningService("HTTP")],
        value=0,
        properties=["Windows7"],
        vulnerabilities=dict(
                Link_Windows8=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.LOCAL,
                    description="Windows8",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Windows8", port="SMB",
                                       credential="Windows8")]),
                    cost=1.0
                ),
                Link_Windows10=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="Windows10",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Windows10", port="RDP",
                                       credential="Windows10")]),
                    cost=1.0
            ),
                Link_SQL_Server_Testing=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="SQL",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="SQL_Server_Testing", port="SSH",
                                       credential="SQL_Server_Testing")]),
                    cost=1.0
            ),
        ),
        agent_installed=True,
        reimagable=False),

    "Windows8":m.NodeInfo(
        services=[m.ListeningService("SMB",allowedCredentials=[
                      "Windows8"])],
        value=0,
        properties=["Windows8"],
        vulnerabilities=dict(
            Link_SQL_Server_Testing=m.VulnerabilityInfo(
                type=m.VulnerabilityType.REMOTE,
                description="SQL",
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="SQL_Server_Testing", port="SSH",
                                       credential="SQL_Server_Testing")]),
                cost=1.0
            ),
            Link_Windows7=m.VulnerabilityInfo(
                type=m.VulnerabilityType.REMOTE,
                description="Windows7",
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="Windows7", port="RDP",
                                       credential="Windows7")]),
                cost=1.0
            )
        ),
    ),

    "Windows10":m.NodeInfo(
        services=[m.ListeningService("RDP",allowedCredentials=[
                      "Windows10"])],
        value=0,
        properties=["Windows10"],
        vulnerabilities=dict(
            Link_SQL_Server_Testing=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="RedHat",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="RedHat", port="SSH",
                                       credential="RedHat_Appache_website")]),
                    cost=1.0
        )
    )),

    "SQL_Server_Testing": m.NodeInfo(
        services=[m.ListeningService("SSH",allowedCredentials=[
                      "SQL_Server_Testing"])],
        value=10,),

    "Windows7":m.NodeInfo(
        services=[m.ListeningService("RDP",allowedCredentials=[
                      "Windows7"])],
        value=0,
        properties=["Windows7"],
        vulnerabilities=dict(
            Link_SQL_Server_Testing=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="IIS",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="IIS", port="HTTP",
                                       credential="IIS_website")]),
                    cost=1.0
        )
    )),

    "RedHat":m.NodeInfo(
        services=[m.ListeningService("SSH",allowedCredentials=[
                      "RedHat_Appache_website"])],
        value=0,
        properties=["RedHat"],
        vulnerabilities=dict(
            Link_SQL_Server_Testing=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="Redis",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Redis", port="SSH",
                                       credential="Redis")]),
                    cost=1.0
        )
    )),

    "IIS":m.NodeInfo(
        services=[m.ListeningService("HTTP",allowedCredentials=[
                      "IIS_website"])],
        value=0,
        properties=["IIS"],
        vulnerabilities=dict(
            Link_SQL_Server_Testing=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="SQL",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="SQL_Server_12", port="SSH",
                                       credential="SQL_Server_12")]),
                    cost=1.0
        )
    )),

    "Redis": m.NodeInfo(
        services=[m.ListeningService("SSH",allowedCredentials=[
                      "Redis"])],
        value=10,),

    "SQL_Server_12": m.NodeInfo(
        services=[m.ListeningService("SSH",allowedCredentials=[
                      "SQL_Server_12"])],
        value=10,),
}


global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])

# Environment constants
ENV_IDENTIFIERS = m.infer_constants_from_nodes(
    cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())),
    global_vulnerability_library)


def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS
    )
