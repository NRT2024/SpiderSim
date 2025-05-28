# SpiderSim - A Network Attack Simulation Environment
# Copyright (c) 2024 NRT

from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple
import sys
import os
import json

# 将AI_Scene_Code_Generate目录添加到路径
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../.."))
ai_code_generate_dir = os.path.join(project_root, "AI_Scene_Code_Generate")
sys.path.append(ai_code_generate_dir)

# AI代码JSON文件路径
AI_CODE_JSON_PATH = os.path.join(project_root, "AI_Code/AI_Code.json")

default_allow_rules = [
    m.FirewallRule("RDP", m.RulePermission.ALLOW),
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
    m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
    m.FirewallRule("HTTP", m.RulePermission.ALLOW),
]

# 从JSON文件中读取生成的代码
def load_code_from_json():
    try:
        # 检查文件是否存在
        if not os.path.exists(AI_CODE_JSON_PATH):
            print(f"警告: AI代码文件 {AI_CODE_JSON_PATH} 不存在。尝试先运行main.py生成代码。")
            return ""
            
        # 读取JSON文件
        with open(AI_CODE_JSON_PATH, 'r') as f:
            code_snippets = json.load(f)
            
        # 如果code_snippets是列表，则将其连接成一个字符串
        if isinstance(code_snippets, list):
            return "\n".join(code_snippets)
        # 如果已经是字符串，则直接返回
        elif isinstance(code_snippets, str):
            return code_snippets
        else:
            print(f"警告: 代码格式无效。")
            return ""
    except Exception as e:
        print(f"读取AI代码文件时出错: {e}")
        return ""

# 读取生成的代码
generated_code = load_code_from_json()

# 初始化空字典来保存结果
nodes = {}

# 使用更简单的方法处理生成的代码
# 将代码包装在一个字典中，然后一次性执行
try:
    # 将生成的代码包装在花括号中，使其成为一个有效的字典字符串
    dict_code = f"{{ {generated_code} }}"
    
    # 创建一个本地命名空间
    local_vars = {"m": m}
    
    # 执行代码，将结果保存到一个变量中
    exec(f"parsed_nodes = {dict_code}", {"m": m}, local_vars)
    
    # 更新nodes字典
    if "parsed_nodes" in local_vars and isinstance(local_vars["parsed_nodes"], dict):
        nodes.update(local_vars["parsed_nodes"])
except Exception as e:
    print(f"处理生成的代码时出错: {e}")

# 如果nodes为空，使用默认节点
if not nodes:
    print("警告: 无法解析生成的代码，使用默认节点")
    nodes = {
        "data_center": m.NodeInfo(
            services=[m.ListeningService("SSH", allowedCredentials=["pwdata_center"])],
            value=1000,
            properties=["Linux", "CentOS", "nginx/1.14.0"],
            owned_string="FLAG: Access granted to data_center",
            agent_installed=True,
            reimagable=False,
        ),
        "edge_computing_node": m.NodeInfo(
            services=[m.ListeningService("SSH", allowedCredentials=["pwedge_computing_node"])],
            value=1000,
            properties=["Ubuntu", "nginx/1.10.3"],
            owned_string="FLAG: Edge computing node successfully compromised",
        ),
    }
else:
    print(f"成功读取并解析了{len(nodes)}个节点")

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