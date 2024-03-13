from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple

default_allow_rules = [
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
    m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
    m.FirewallRule("HTTP", m.RulePermission.ALLOW),
    m.FirewallRule("SMB", m.RulePermission.ALLOW),
    m.FirewallRule("OSC", m.RulePermission.ALLOW),
    m.FirewallRule("RTP", m.RulePermission.ALLOW)
]


nodes = {
    "Digital_Model_Static": m.NodeInfo(
        services=[m.ListeningService("SSH")],
        value=100,
        properties=["Digital_Model"],
        vulnerabilities=dict(
                Link_Camera=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.LOCAL,
                    description="Camera",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Camera", port="SMB",
                                       credential="Camera")]),
                    cost=1.0
                ),
                Link_Microphoone=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="Microphoone",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Microphoone", port="SMB",
                                       credential="Microphoone")]),
                    cost=1.0
            ),
                Link_Mobile_Capture=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="Mobile_Capture",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Mobile_Capture", port="SMB",
                                       credential="Mobile_Capture")]),
                    cost=1.0
            ),
        ),
        agent_installed=True,
        reimagable=False),

    "Camera":m.NodeInfo(
        services=[m.ListeningService("SMB",allowedCredentials=[
                      "Camera"])],
        value=500,
        properties=["Camera"],
        vulnerabilities=dict(
            Link_Image_processing=m.VulnerabilityInfo(
                type=m.VulnerabilityType.REMOTE,
                description="Camera",
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="Image_processing", port="OSC",
                                       credential="Image_processing")]),
                cost=1.0
            ),
        ),
    ),

    "Microphoone":m.NodeInfo(
        services=[m.ListeningService("SMB",allowedCredentials=[
                      "Microphoone"])],
        value=500,
        properties=["Microphoone"],
        vulnerabilities=dict(
            Link_Speech_processing=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="Speech_processing",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Speech_processing", port="RTP",
                                       credential="Speech_processing")]),
                    cost=1.0
        )
    )),

    "Mobile_Capture":m.NodeInfo(
        services=[m.ListeningService("SMB",allowedCredentials=[
                      "Mobile_Capture"])],
        value=500,
        properties=["Mobile_Capture"],
        vulnerabilities=dict(
            Link_Mobile_Capture_processing=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="Mobile_Capture_processing",
                    outcome=m.LeakedNodesId(["Mobile_Capture_processing"]),
                    cost=1.0
        )
    )),

    "Image_processing":m.NodeInfo(
        services=[m.ListeningService("OSC",allowedCredentials=[
                      "Image_processing"])],
        value=1000,
        properties=["Image_processing"],
        vulnerabilities=dict(
            Link_Digital_Human=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="Digital_Human",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Digital_Human", port="OSC",
                                       credential="Digital_Human_I")]),
                    cost=1.0
        )
    )),

    "Speech_processing":m.NodeInfo(
        services=[m.ListeningService("RTP",allowedCredentials=[
                      "Speech_processing"])],
        value=1000,
        properties=["Speech_processing"],
        vulnerabilities=dict(
            Link_Digital_Human=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="Digital_Human",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Digital_Human", port="RTP",
                                       credential="Digital_Human_S")]),
                    cost=1.0
        )
    )),

    "Mobile_Capture_processing":m.NodeInfo(
        services=[m.ListeningService("SSH")],
        value=1000,
        properties=["Mobile_Capture_processing"],
        vulnerabilities=dict(
            Link_Digital_Human=m.VulnerabilityInfo(
                    type=m.VulnerabilityType.REMOTE,
                    description="Digital_Human",
                    outcome=m.LeakedCredentials(credentials=[
                            m.CachedCredential(node="Digital_Human", port="SSH",
                                       credential="Digital_Human_M")]),
                    cost=1.0
        )
    )),

    "Digital_Human": m.NodeInfo(
        services=[m.ListeningService("OSC", allowedCredentials=["Digital_Human_I"]),
                  m.ListeningService("RTP", allowedCredentials=["Digital_Human_S"]),
                  m.ListeningService("SSH", allowedCredentials=["Digital_Human_M"])],
        value=2000,),
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
