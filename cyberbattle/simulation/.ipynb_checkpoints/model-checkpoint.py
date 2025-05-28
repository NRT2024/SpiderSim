# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""仿真环境的数据模型。

仿真环境由如下定义的有向图给出：

  节点 := NodeID x ListeningService[] x Value x Vulnerability[] x FirewallConfig
  边 := NodeID x NodeID x PortName

 其中：
  - NodeID: 字符串
  - ListeningService : Name x AllowedCredentials
  - AllowedCredentials : 字符串[]  # 仅通过字符串ID表示的凭证对
  - Value : [0...100]     # 到达此节点的固有价值
  - Vulnerability : VulnerabilityID x 类型 x 先决条件 x 结果 x 概率
  - VulnerabilityID : 字符串
  - 概率 : ProbingDetectionRate x ExploitDetectionRate x SuccessRate
  - FirewallConfig: {
      outgoing :  FirwallRule[]
      incoming : FirwallRule [] }
  - FirewallRule: PortName x { ALLOW, BLOCK }
"""

from datetime import datetime
from typing import NamedTuple, List, Dict, Optional, Union, Tuple, Iterator
import dataclasses
from dataclasses import dataclass, field
import matplotlib.pyplot as plt  # type:ignore
from enum import Enum, IntEnum
from boolean import boolean
import networkx as nx
import yaml
import random

import matplotlib  # type: ignore

matplotlib.use("Agg")

VERSION_TAG = "0.1.0"

ALGEBRA = boolean.BooleanAlgebra()

# 标识符的类型别名
NodeID = str

# 唯一标识符
ID = str

# (登录名,密码/令牌)凭证对抽象为唯一的
# 字符串标识符
CredentialID = str

# 到达指定节点的固有价值[0,100]
NodeValue = int


PortName = str


@dataclass
class ListeningService:
    """给定节点上的服务端口，接受使用指定凭证发起的连接"""

    # 服务监听的端口名称
    name: PortName
    # 允许使用此服务的凭证
    allowedCredentials: List[CredentialID] = dataclasses.field(default_factory=list)
    # 服务是否正在运行
    running: bool = True
    # 用于评估停止服务的成本的权重
    sla_weight = 1.0


x = ListeningService(name="d")
VulnerabilityID = str

# 概率率
Probability = float

# 表示给定节点上服务、组件、功能或漏洞存在的节点属性名称
PropertyName = str


class Rates(NamedTuple):
    """与给定漏洞相关的概率"""

    probingDetectionRate: Probability = 0.0
    exploitDetectionRate: Probability = 0.0
    successRate: Probability = 1.0


class VulnerabilityType(Enum):
    """漏洞是否可以本地或远程利用"""

    LOCAL = 1
    REMOTE = 2


class PrivilegeLevel(IntEnum):
    """给定节点上的访问特权级别"""

    NoAccess = 0
    LocalUser = 1
    Admin = 2
    System = 3
    MAXIMUM = 3


def escalate(current_level, escalation_level: PrivilegeLevel) -> PrivilegeLevel:
    return PrivilegeLevel(max(int(current_level), int(escalation_level)))


class VulnerabilityOutcome:
    """利用给定漏洞的结果"""


class LateralMove(VulnerabilityOutcome):
    """横向移动到目标节点"""

    success: bool


class CustomerData(VulnerabilityOutcome):
    """访问目标节点上的客户数据"""


class PrivilegeEscalation(VulnerabilityOutcome):
    """特权升级结果"""

    def __init__(self, level: PrivilegeLevel):
        self.level = level

    @property
    def tag(self):
        """当特权级别达到该节点时，添加到节点属性中的升级标签"""
        return f"privilege_{self.level}"


class SystemEscalation(PrivilegeEscalation):
    """升级到SYSTEM特权"""

    def __init__(self):
        super().__init__(PrivilegeLevel.System)


class AdminEscalation(PrivilegeEscalation):
    """升级到本地管理员特权"""

    def __init__(self):
        super().__init__(PrivilegeLevel.Admin)


class ProbeSucceeded(VulnerabilityOutcome):
    """探测成功"""

    def __init__(self, discovered_properties: List[PropertyName]):
        self.discovered_properties = discovered_properties


class ProbeFailed(VulnerabilityOutcome):
    """探测失败"""


class ExploitFailed(VulnerabilityOutcome):
    """当漏洞利用失败时的结果"""


class CachedCredential(NamedTuple):
    """编码计算机端口凭证三元组"""

    node: NodeID
    port: PortName
    credential: CredentialID


class LeakedCredentials(VulnerabilityOutcome):
    """通过利用漏洞泄露的凭证集"""

    credentials: List[CachedCredential]

    def __init__(self, credentials: List[CachedCredential]):
        self.credentials = credentials


class LeakedNodesId(VulnerabilityOutcome):
    """通过利用漏洞泄露的节点ID集"""

    def __init__(self, nodes: List[NodeID]):
        self.nodes = nodes


VulnerabilityOutcomes = Union[LeakedCredentials, LeakedNodesId, PrivilegeEscalation, AdminEscalation, SystemEscalation, CustomerData, LateralMove, ExploitFailed]

class AttackResult:
    """尝试特定攻击（本地或远程）的结果"""

    success: bool
    expected_outcome: Union[VulnerabilityOutcomes, None]


class Precondition:
    """定义给定功能或漏洞存在或不存在的条件的谓词逻辑表达式。
    表达式中使用的符号指的是与相应节点相关的属性。
    例如：'Win7'、'Server'、'IISInstalled'、'SQLServerInstalled'、
    'AntivirusInstalled' 等...
    """

    expression: boolean.Expression

    def __init__(self, expression: Union[boolean.Expression, str]):
        if isinstance(expression, boolean.Expression):
            self.expression = expression
        else:
            self.expression = ALGEBRA.parse(expression)


class VulnerabilityInfo(NamedTuple):
    """已知漏洞的定义"""

    # 可选的漏洞描述
    description: str
    # 漏洞类型
    type: VulnerabilityType
    # 成功利用漏洞后发生的事情
    outcome: VulnerabilityOutcome
    # 确定漏洞是否存在的布尔表达式
    precondition: Precondition = Precondition("true")
    # 与此漏洞相关的成功/失败概率
    rates: Rates = Rates()
    # 指向漏洞信息的URL
    URL: str = ""
    # 与利用该漏洞相关的一些成本（例如，暴力破解比获取凭证更昂贵）
    cost: float = 1.0
    # 漏洞成功利用时显示的字符串
    reward_string: str = ""


# 存储仿真中所有支持的漏洞或功能信息的字典。
# 这是在启动仿真之前预填充的全局字典，并根据现实世界的数据进行估算。
VulnerabilityLibrary = Dict[VulnerabilityID, VulnerabilityInfo]


class RulePermission(Enum):
    """确定规则是允许还是阻止流量"""

    ALLOW = 0
    BLOCK = 1


@dataclass(frozen=True)
class FirewallRule:
    """防火墙规则"""

    # 端口名称
    port: PortName
    # 该端口上的权限
    permission: RulePermission
    # 阻止/允许规则的可选理由
    reason: str = ""


@dataclass
class FirewallConfiguration:
    """给定节点的防火墙配置。
    确定在给定端口上对出站和入站流量的允许或阻止。
    规则按顺序处理：匹配给定端口的第一个规则将被应用，后续规则将被忽略。

    配置中未列出的端口默认为被阻止。（添加显式阻止规则
    仍然有助于给出阻止的理由。）
    """

    outgoing: List[FirewallRule] = field(
        repr=True,
        default_factory=lambda: [
            FirewallRule("RDP", RulePermission.ALLOW),
            FirewallRule("SSH", RulePermission.ALLOW),
            FirewallRule("HTTPS", RulePermission.ALLOW),
            FirewallRule("HTTP", RulePermission.ALLOW),
        ],
    )
    incoming: List[FirewallRule] = field(
        repr=True,
        default_factory=lambda: [
            FirewallRule("RDP", RulePermission.ALLOW),
            FirewallRule("SSH", RulePermission.ALLOW),
            FirewallRule("HTTPS", RulePermission.ALLOW),
            FirewallRule("HTTP", RulePermission.ALLOW),
        ],
    )


class MachineStatus(Enum):
    """机器运行状态"""

    Stopped = 0
    Running = 1
    Imaging = 2


@dataclass
class NodeInfo:
    """企业网络中的计算机节点"""

    # 节点监听的端口/协议列表
    services: List[ListeningService]
    # 节点已知漏洞列表
    vulnerabilities: VulnerabilityLibrary = dataclasses.field(default_factory=dict)
    # 节点的固有价值（如果节点被占领，则转化为奖励）
    value: NodeValue = 0
    # 节点的属性，其中一些属性可能意味着进一步的漏洞
    properties: List[PropertyName] = dataclasses.field(default_factory=list)
    # 节点的防火墙配置
    firewall: FirewallConfiguration = FirewallConfiguration()
    # 节点上是否安装了攻击代理？（即节点是否被'攻陷'）
    agent_installed: bool = False
    # 节点的特权级别
    privilege_level: PrivilegeLevel = PrivilegeLevel.NoAccess
    # 节点是否可以被防御者代理重新映像？
    reimagable: bool = True
    # 节点最后一次被重新映像的时间
    last_reimaging: Optional[datetime] = None
    # 节点被攻陷时显示的字符串
    owned_string: str = ""
    # 机器状态：运行中或停止
    status = MachineStatus.Running
    # 用于计算停止此机器或其服务成本的相对节点权重
    sla_weight: float = 1.0
class Identifiers(NamedTuple):
    """定义给定环境中使用的全局标识符集。
    这样的集合定义了一个共享的公共词汇，可能
    跨多个环境共享，从而确保一致的编号约定，
    使得机器学习模型可以从中学习。
    """

    # 所有可能的节点属性标识符数组
    properties: List[PropertyName] = []
    # 所有可能的端口名称数组
    ports: List[PortName] = ["Null"]
    # 所有可能的本地漏洞名称数组
    local_vulnerabilities: List[VulnerabilityID] = []
    # 所有可能的远程漏洞名称数组
    remote_vulnerabilities: List[VulnerabilityID] = []


def iterate_network_nodes(network: nx.graph.Graph) -> Iterator[Tuple[NodeID, NodeInfo]]:
    """遍历网络中的节点"""
    for nodeid, nodevalue in network.nodes.items():
        node_data: NodeInfo = nodevalue["data"]
        yield nodeid, node_data


# 注意：使用 `NamedTuple` 而不是 `dataclass` 会导致 PyYaml 2.8.1 中的反序列化失败，
# 因为该版本中的网络x图存在新的递归引用：
#   edges: !!python/object:networkx.classes.reportviews.EdgeView
#     _adjdict: *id018
#     _graph: *id019
@dataclass
class Environment:
    """定义计算机网络的静态图"""

    network: nx.DiGraph
    vulnerability_library: VulnerabilityLibrary
    identifiers: Identifiers
    creationTime: datetime = datetime.utcnow()
    lastModified: datetime = datetime.utcnow()
    # 用于指示环境架构版本的版本标签
    version: str = VERSION_TAG

    def nodes(self) -> Iterator[Tuple[NodeID, NodeInfo]]:
        """遍历网络中的节点"""
        return iterate_network_nodes(self.network)

    def get_node(self, node_id: NodeID) -> NodeInfo:
        """检索指定ID节点的详细信息"""
        node_info: NodeInfo = self.network.nodes[node_id]["data"]
        return node_info

    def plot_environment_graph(self) -> None:
        """绘制完整的环境图"""
        nx.draw(self.network, with_labels=True, node_color=[n["data"].value for i, n in self.network.nodes.items()], cmap=plt.cm.Oranges)  # type:ignore


def create_network(nodes: Dict[NodeID, NodeInfo]) -> nx.DiGraph:
    """使用一组节点创建一个没有边的网络"""
    graph = nx.DiGraph()
    graph.add_nodes_from([(k, {"data": v}) for (k, v) in list(nodes.items())])
    return graph


# 帮助函数，用于从环境中推断常量


def collect_ports_from_vuln(vuln: VulnerabilityInfo) -> List[PortName]:
    """返回给定漏洞中引用的所有端口名称"""
    if isinstance(vuln.outcome, LeakedCredentials):
        return [c.port for c in vuln.outcome.credentials]
    else:
        return []


def collect_vulnerability_ids_from_nodes_bytype(nodes: Iterator[Tuple[NodeID, NodeInfo]], global_vulnerabilities: VulnerabilityLibrary, type: VulnerabilityType) -> List[VulnerabilityID]:
    """收集并返回给定节点和漏洞库中指定类型的所有漏洞ID"""
    return sorted(list({id for _, node_info in nodes for id, v in node_info.vulnerabilities.items() if v.type == type}.union(id for id, v in global_vulnerabilities.items() if v.type == type)))


def collect_properties_from_nodes(nodes: Iterator[Tuple[NodeID, NodeInfo]]) -> List[PropertyName]:
    """收集并返回给定节点中使用的所有属性名称的排序列表"""
    return sorted({p for _, node_info in nodes for p in node_info.properties})


def collect_ports_from_nodes(nodes: Iterator[Tuple[NodeID, NodeInfo]], vulnerability_library: VulnerabilityLibrary) -> List[PortName]:
    """收集并返回给定节点和全局漏洞库中使用的所有端口名称"""
    return sorted(
        list(
            {port for _, v in vulnerability_library.items() for port in collect_ports_from_vuln(v)}.union(
                {port for _, node_info in nodes for _, v in node_info.vulnerabilities.items() for port in collect_ports_from_vuln(v)}.union(
                    {service.name for _, node_info in nodes for service in node_info.services}
                )
            )
        )
    )


def collect_ports_from_environment(environment: Environment) -> List[PortName]:
    """收集并返回给定环境中使用的所有端口名称"""
    return collect_ports_from_nodes(environment.nodes(), environment.vulnerability_library)


def infer_constants_from_nodes(nodes: Iterator[Tuple[NodeID, NodeInfo]], vulnerabilities: Dict[VulnerabilityID, VulnerabilityInfo]) -> Identifiers:
    """从给定网络推断全局环境常量"""
    return Identifiers(
        properties=collect_properties_from_nodes(nodes),
        ports=collect_ports_from_nodes(nodes, vulnerabilities),
        local_vulnerabilities=collect_vulnerability_ids_from_nodes_bytype(nodes, vulnerabilities, VulnerabilityType.LOCAL),
        remote_vulnerabilities=collect_vulnerability_ids_from_nodes_bytype(nodes, vulnerabilities, VulnerabilityType.REMOTE),
    )


def infer_constants_from_network(network: nx.Graph, vulnerabilities: Dict[VulnerabilityID, VulnerabilityInfo]) -> Identifiers:
    """从给定网络推断全局环境常量"""
    return infer_constants_from_nodes(iterate_network_nodes(network), vulnerabilities)


# 网络创建

# 一个环境常量的示例集合
SAMPLE_IDENTIFIERS = Identifiers(
    ports=["RDP", "SSH", "SMB", "HTTP", "HTTPS", "WMI", "SQL"], properties=["Windows", "Linux", "HyperV-VM", "Azure-VM", "Win7", "Win10", "PortRDPOpen", "GuestAccountEnabled"]
)


def assign_random_labels(graph: nx.DiGraph, vulnerabilities: VulnerabilityLibrary = dict([]), identifiers: Identifiers = SAMPLE_IDENTIFIERS) -> nx.DiGraph:
    """通过随机分配节点信息（属性、防火墙配置、漏洞）
    来创建一个环境网络
    """

    # 将节点ID转换为字符串
    graph = nx.relabel_nodes(graph, {i: str(i) for i in graph.nodes})

    def create_random_firewall_configuration() -> FirewallConfiguration:
        return FirewallConfiguration(
            outgoing=[FirewallRule(port=p, permission=RulePermission.ALLOW) for p in random.sample(identifiers.ports, k=random.randint(0, len(identifiers.ports)))],
            incoming=[FirewallRule(port=p, permission=RulePermission.ALLOW) for p in random.sample(identifiers.ports, k=random.randint(0, len(identifiers.ports)))],
        )

    def create_random_properties() -> List[PropertyName]:
        return list(random.sample(identifiers.properties, k=random.randint(0, len(identifiers.properties))))

    def pick_random_global_vulnerabilities() -> VulnerabilityLibrary:
        count = random.random()
        return {k: v for (k, v) in vulnerabilities.items() if random.random() > count}

    def add_leak_neighbors_vulnerability(library: VulnerabilityLibrary, node_id: NodeID) -> None:
        """为每个节点创建一个漏洞，揭示其直接邻居"""
        neighbors = {t for (s, t) in graph.edges() if s == node_id}
        if len(neighbors) > 0:
            library["RecentlyAccessedMachines"] = VulnerabilityInfo(description="AzureVM信息，包括公网IP地址", type=VulnerabilityType.LOCAL, outcome=LeakedNodesId(list(neighbors)))

    def create_random_vulnerabilities(node_id: NodeID) -> VulnerabilityLibrary:
        library = pick_random_global_vulnerabilities()
        add_leak_neighbors_vulnerability(library, node_id)
        return library

    # 随机选择一个节点作为代理入口节点
    entry_node_index = random.randrange(len(graph.nodes))
    entry_node_id, entry_node_data = list(graph.nodes(data=True))[entry_node_index]
    graph.nodes[entry_node_id].clear()
    node_data = NodeInfo(
        services=[],
        value=0,
        properties=create_random_properties(),
        vulnerabilities=create_random_vulnerabilities(entry_node_id),
        firewall=create_random_firewall_configuration(),
        agent_installed=True,
        reimagable=False,
        privilege_level=PrivilegeLevel.Admin,
    )
    graph.nodes[entry_node_id].update({"data": node_data})

    def create_random_node_data(node_id: NodeID) -> NodeInfo:
        return NodeInfo(
            services=[],
            value=random.randint(0, 100),
            properties=create_random_properties(),
            vulnerabilities=create_random_vulnerabilities(node_id),
            firewall=create_random_firewall_configuration(),
            agent_installed=False,
            privilege_level=PrivilegeLevel.NoAccess,
        )

    for node in list(graph.nodes):
        if node != entry_node_id:
            graph.nodes[node].clear()
            graph.nodes[node].update({"data": create_random_node_data(node)})

    return graph


# 序列化
def setup_yaml_serializer() -> None:
    """为环境类型对象设置干净的YAML格式化程序。"""
    yaml.add_representer(Precondition, lambda dumper, data: dumper.represent_scalar("!BooleanExpression", str(data.expression)))  # type: ignore
    yaml.SafeLoader.add_constructor("!BooleanExpression", lambda loader, expression: Precondition(loader.construct_scalar(expression)))  # type: ignore
    yaml.add_constructor("!BooleanExpression", lambda loader, expression: Precondition(loader.construct_scalar(expression)))  # type: ignore

    yaml.add_representer(VulnerabilityType, lambda dumper, data: dumper.represent_scalar("!VulnerabilityType", str(data.name)))  # type: ignore

    yaml.SafeLoader.add_constructor("!VulnerabilityType", lambda loader, expression: VulnerabilityType[loader.construct_scalar(expression)])  # type: ignore
    yaml.add_constructor("!VulnerabilityType", lambda loader, expression: VulnerabilityType[loader.construct_scalar(expression)])  # type: ignore
