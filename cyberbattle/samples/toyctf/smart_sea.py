
"""Model a toy Capture the flag exercise

See Jupyter notebook toyctf-simulation.ipynb for an example of
game played on this simulation.
"""
from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple

default_allow_rules = [
    m.FirewallRule("RDP", m.RulePermission.ALLOW),
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
    m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
    m.FirewallRule("HTTP", m.RulePermission.ALLOW)]

# Network nodes involved in the Capture the flag game
nodes = {
    "Internet": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],
        value=0,
        properties=["Internet"],
        vulnerabilities=dict(
                Link_client=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.LOCAL,
                    description="client",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Client", port="HTTPS",
                                       credential="Clients")]),
                    cost=1.0
                ),
                Link_server=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="server",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Server", port="HTTPS",
                                       credential="Server")]),
                    cost=1.0
            ),
        ),
        agent_installed=True,
        reimagable=False),

    "Client": m.NodeInfo(
        services=[m.ListeningService("HTTPS", allowedCredentials=[
                      "Clients"])],

        value=10,
    ),
    "Server": m.NodeInfo(
        services=[m.ListeningService("HTTPS",allowedCredentials=[
                      "Server"])],
        value=10,
        vulnerabilities=dict(
                Link_IPC=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.LOCAL,
                    description="IPC",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="IPC", port="HTTPS",
                                       credential="IPC")]),
                    cost=1.0
                ),
    )),
    "IPC": m.NodeInfo(
        services=[m.ListeningService("HTTPS",allowedCredentials=[
                      "IPC"])],
        value=10,
        vulnerabilities=dict(
                Link_Microwave=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.LOCAL,
                    description="Microwave",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Microwave", port="HTTPS",
                                       credential="Microwave")]),
                    cost=1.0
                ),
                Link_3G=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.LOCAL,
                    description="3G",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="3G", port="HTTPS",
                                       credential="3G")]),
                    cost=1.0
                ),
    )),
    "Microwave": m.NodeInfo(
        services=[m.ListeningService("HTTPS",allowedCredentials=[
                      "Microwave"])],
        value=10,
        vulnerabilities=dict(
            Link_Camera=m.VulnerabilityInfo(
                type=m.VulnerabilityType.REMOTE,
                description="Camera",
                outcome=m.LeakedNodesId(["Camera"]),
                cost=1.0
        ),
    )),
    "Camera": m.NodeInfo(
        services=[m.ListeningService("SSH")],
        value=10,
    ),
    "3G": m.NodeInfo(
        services=[m.ListeningService("HTTPS",allowedCredentials=[
                      "3G"])],
        value=10,
        vulnerabilities=dict(
            Link_MCN=m.VulnerabilityInfo(
                type=m.VulnerabilityType.LOCAL,
                description="MCN",
                outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="MCN", port="HTTPS",
                                       credential="MCN")]),
                cost=1.0
        ),
    )),
    "MCN": m.NodeInfo(
        services=[m.ListeningService("HTTPS",allowedCredentials=[
                      "MCN"])],
        value=10,
        vulnerabilities=dict(
            Link_DAU=m.VulnerabilityInfo(
                type=m.VulnerabilityType.LOCAL,
                description="DAU",
                outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="DAU", port="HTTPS",
                                       credential="DAU")]),
                cost=1.0
        ),
    )),
    "DAU": m.NodeInfo(
        services=[m.ListeningService("HTTPS",allowedCredentials=[
                      "DAU"])],
        value=10,
        vulnerabilities=dict(
            Link_TAHS=m.VulnerabilityInfo(
                type=m.VulnerabilityType.REMOTE,
                description="TAHS",
                outcome=m.LeakedNodesId(["TAHS"]),
                cost=1.0
        ),
            Link_WSADS=m.VulnerabilityInfo(
                type=m.VulnerabilityType.REMOTE,
                description="WSADS",
                outcome=m.LeakedNodesId(["WSADS"]),
                cost=1.0
        ),
            Link_CTD=m.VulnerabilityInfo(
                type=m.VulnerabilityType.REMOTE,
                description="CTD",
                outcome=m.LeakedNodesId(["CTD"]),
                cost=1.0
        ),
            Link_ADCP=m.VulnerabilityInfo(
                type=m.VulnerabilityType.REMOTE,
                description="ADCP",
                outcome=m.LeakedNodesId(["ADCP"]),
                cost=1.0
        ),
            Link_ZigBee=m.VulnerabilityInfo(
                type=m.VulnerabilityType.REMOTE,
                description="ZigBee",
                outcome=m.LeakedNodesId(["ZigBee"]),
                cost=1.0
        ),
    )),
    "TAHS": m.NodeInfo(
        services=[m.ListeningService("SSH")],
        value=10,
    ),
    "WSADS": m.NodeInfo(
        services=[m.ListeningService("SSH")],
        value=10,
    ),
    "CTD": m.NodeInfo(
        services=[m.ListeningService("SSH")],
        value=10,
    ),
    "ADCP": m.NodeInfo(
        services=[m.ListeningService("SSH")],
        value=10,
    ),
    "ZigBee": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],
        value=10,
        vulnerabilities=dict(
            Link_SinkNode=m.VulnerabilityInfo(
                type=m.VulnerabilityType.REMOTE,
                description="SinkNode",
                outcome=m.LeakedNodesId(["SinkNode"]),
                cost=1.0
            ),
        )),
    "SinkNode": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],
        value=10,
        vulnerabilities=dict(
            Link_SensorNode=m.VulnerabilityInfo(
                type=m.VulnerabilityType.REMOTE,
                description="SensorNode",
                outcome=m.LeakedNodesId(["SensorNode"]),
                cost=1.0
            ),
        )),
    "SensorNode": m.NodeInfo(
        services=[m.ListeningService("SSH")],
        value=10,
    ),
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