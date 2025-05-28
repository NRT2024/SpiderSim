# SpiderSim - A Network Attack Simulation Environment
# Copyright (c) 2024 NRT

from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple
import json
import os

default_allow_rules = [
    m.FirewallRule("RDP", m.RulePermission.ALLOW),
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
    m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
    m.FirewallRule("HTTP", m.RulePermission.ALLOW),
]



current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../.."))
ai_code_path = os.path.join(project_root, "AI_Code", "AI_Code.json")

# 读取 JSON 文件
# with open(ai_code_path, "rb", encoding="utf-8") as f:
with open(ai_code_path, "r", encoding="utf-8") as f:
    # pass
    input_list = json.load(f)  # input_str 是一个字符串
# input_list=['"data_center": m.NodeInfo(\n    services=[m.ListeningService("SSH", allowedCredentials=["pwdata_center"])],\n    value=1000,\n    properties=["Ubuntu", "nginx/1.10.3"],\n    agent_installed=True,\n    reimagable=False,\n    owned_string="FLAG: Login using insecure SSH user/password",\n    vulnerabilities=dict(\n        ConnectToEdgeComputingNode=m.VulnerabilityInfo(\n            description="Remote connection to edge_computing_node",\n            type=m.VulnerabilityType.REMOTE,\n            outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="edge_computing_node", port="SSH", credential="pwedge_computing_node")]),\n            reward_string="FLAG: Successfully connected to edge_computing_node",\n            cost=1.0,\n        ),\n    ),\n),\n', '"edge_computing_node": m.NodeInfo(\n    services=[m.ListeningService("SSH", allowedCredentials=["pwedge_computing_node"])],\n    value=1000,\n    properties=["Ubuntu", "nginx/1.10.3"],\n    owned_string="FLAG: Login using insecure SSH user/password",\n    vulnerabilities=dict(\n        ConnectToEnvironmentalMonitoringBuoy=m.VulnerabilityInfo(\n            description="Remote connection to environmental_monitoring_buoy",\n            type=m.VulnerabilityType.REMOTE,\n            outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="environmental_monitoring_buoy", port="SSH", credential="pwenvironmental_monitoring_buoy")]),\n            reward_string="FLAG: Successfully connected to environmental_monitoring_buoy",\n            cost=1.0,\n        ),\n        ConnectToBiologicalMonitoringSubmersible=m.VulnerabilityInfo(\n            description="Remote connection to biological_monitoring_submersible",\n            type=m.VulnerabilityType.REMOTE,\n            outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="biological_monitoring_submersible", port="SSH", credential="pwbiological_monitoring_submersible")]),\n            reward_string="FLAG: Successfully connected to biological_monitoring_submersible",\n            cost=1.0,\n        ),\n        ConnectToHighFrequencyRadar=m.VulnerabilityInfo(\n            description="Remote connection to high_frequency_radar",\n            type=m.VulnerabilityType.REMOTE,\n            outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="high_frequency_radar", port="SSH", credential="pwhigh_frequency_radar")]),\n            reward_string="FLAG: Successfully connected to high_frequency_radar",\n            cost=1.0,\n        ),\n        ConnectToDataCenter=m.VulnerabilityInfo(\n            description="Local connection to data_center",\n            type=m.VulnerabilityType.LOCAL,\n            outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="data_center", port="SSH", credential="pwdata_center")]),\n            reward_string="FLAG: Successfully connected to data_center",\n            cost=1.0,\n        ),\n    ),\n),\n', '"environmental_monitoring_buoy": m.NodeInfo(\n    services=[m.ListeningService("HTTPS")],\n    value=1000,\n    properties=["EnvironmentalSensor", "Ubuntu", "nginx/1.10.3"],\n    owned_string="FLAG: Environmental monitoring buoy compromised",\n),\n', '"biological_monitoring_submersible": m.NodeInfo(\n    services=[m.ListeningService("HTTPS")],\n    value=1000,\n    properties=["Submersible", "BiologicalMonitoring", "Underwater"],\n    owned_string="FLAG: Biological monitoring submersible compromised",\n),\n', '"high_frequency_radar": m.NodeInfo(\n    services=[m.ListeningService("HTTPS")],\n    value=1000,\n    properties=["Radar", "HighFrequency", "Ubuntu"],\n    owned_string="FLAG: High Frequency Radar system compromised",\n),\n', '"drone": m.NodeInfo(\n    services=[m.ListeningService("SSH", allowedCredentials=["pwdata_center"])],\n    value=1000,\n    properties=["Ubuntu", "DroneOS"],\n    owned_string="FLAG: Drone compromised!",\n    vulnerabilities=dict(\n        RemoteConnection=m.VulnerabilityInfo(\n            description="Remote connection to data_center",\n            type=m.VulnerabilityType.REMOTE,\n            outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="data_center", port="SSH", credential="pwdata_center")]),\n            reward_string="FLAG: Successfully connected to data_center!",\n            cost=1.0,\n        ),\n    ),\n),\n', '"satellite": m.NodeInfo(\n    services=[m.ListeningService("SSH", allowedCredentials=["pwdata_center"])],\n    value=1000,\n    properties=["Satellite", "RemoteConnection"],\n    owned_string="FLAG: Satellite node owned",\n    vulnerabilities=dict(\n        RemoteConnection=m.VulnerabilityInfo(\n            description="Remote connection to data_center",\n            type=m.VulnerabilityType.REMOTE,\n            outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="data_center", port="SSH", credential="pwdata_center")]),\n            reward_string="FLAG: Successfully connected to data_center via SSH",\n            cost=1.0,\n        ),\n    ),\n),\n', '"data_acquisition_and_preprocessing_system": m.NodeInfo(\n    services=[m.ListeningService("HTTPS")],\n    value=1000,\n    properties=["Ubuntu", "nginx/1.10.3"],\n    owned_string="FLAG: Login using insecure SSH user/password",\n),\n', '"big_data_analysis_platform": m.NodeInfo(\n    services=[m.ListeningService("HTTPS")],\n    value=1000,\n    properties=["Hadoop", "Spark", "Ubuntu"],\n    owned_string="FLAG: Big data platform compromised!",\n),\n', '"intelligent_control_system": m.NodeInfo(\n    services=[m.ListeningService("SSH")],\n    value=1000,\n    properties=["Ubuntu", "nginx/1.10.3"],\n    owned_string="FLAG: Login using insecure SSH user/password",\n),\n', '"expert_consultation_system": m.NodeInfo(\n    services=[m.ListeningService("HTTPS")],\n    value=1000,\n    properties=["Ubuntu", "nginx/1.10.3"],\n    owned_string="FLAG: Login using insecure HTTPS user/password",\n),\n', '"warning_release_system": m.NodeInfo(\n    services=[m.ListeningService("HTTPS")],\n    value=1000,\n    properties=["Ubuntu", "nginx/1.10.3"],\n    owned_string="FLAG: Warning release system compromised",\n),\n']




# 初始化空字典来保存结果
nodes = {}

# 循环处理每个字符串，将其合并到 combined_config 字典中
for code in input_list:
    exec(f"combined_config.update({{{code}}})", globals(), {"combined_config": nodes})


global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])

# Environment constants
ENV_IDENTIFIERS = m.infer_constants_from_nodes(cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())), global_vulnerability_library)

def new_environment() -> m.Environment:
    return m.Environment(network=m.create_network(nodes), vulnerability_library=global_vulnerability_library, identifiers=ENV_IDENTIFIERS)
    