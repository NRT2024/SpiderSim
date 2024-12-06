
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
    input_list = json.load(f)  # input_str 是一个字符串


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
    