# SpiderSim - A Network Attack Simulation Environment
# Copyright (c) 2024 NRT

# This project includes code modified from CyberBattle 
# (https://github.com/microsoft/CyberBattleSim/tree/main/cyberbattle) used under Licensed under the MIT License.



"""Anatares OpenGym 环境实现：网络攻击模拟的强化学习环境"""

import time
import copy
import logging
import networkx
from networkx import convert_matrix
from typing import NamedTuple, Optional, Tuple, List, Dict, TypeVar, TypedDict, cast

import numpy
import gym
from gym import spaces
from gym.utils import seeding

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from cyberbattle._env.defender import DefenderAgent
from cyberbattle.simulation.model import PortName, PrivilegeLevel
from ..simulation import commandcontrol, model, actions
from ..simulation.commandcontrol import EnvironmentDebugging
from .discriminatedunion import DiscriminatedUnion

LOGGER = logging.getLogger(__name__)

# ------------------------- 常量定义 -------------------------
NA = 1  # 用于表示离散空间中'不适用'的默认值
UNUSED_SLOT = numpy.int32(0)  # 表示空间槽位未使用
USED_SLOT = numpy.int32(1)    # 表示空间槽位已使用


# ------------------------- 类型定义 -------------------------
# 动作空间字典类型（用于定义Gym动作空间）
ActionSpaceDict = TypedDict(
    'ActionSpaceDict', {
        'local_vulnerability': spaces.Space,   # 本地漏洞利用动作空间
        'remote_vulnerability': spaces.Space,  # 远程漏洞利用动作空间 
        'connect': spaces.Space,                # 连接动作空间
        'exploit_computation_leak': spaces.Space  # 算力劫持漏洞动作空间
    })

# 动作样本类型
Action = TypedDict(
    'Action', {
        'local_vulnerability': numpy.ndarray,   # 本地攻击：[源节点索引, 漏洞索引]
        'remote_vulnerability': numpy.ndarray,  # 远程攻击：[源节点, 目标节点, 漏洞索引]
        'connect': numpy.ndarray,                # 连接：[源节点, 目标节点, 端口索引, 凭据索引]
        'exploit_computation_leak': numpy.ndarray  # 算力劫持漏洞：[源节点, 目标节点, 漏洞索引]
    }, total=False)

# 来自 ActionMask 空间的样本类型
ActionMask = TypedDict(
    "ActionMask",
    {
        "local_vulnerability": numpy.ndarray,
        "remote_vulnerability": numpy.ndarray,
        "connect": numpy.ndarray,
        "exploit_computation_leak": numpy.ndarray
    },
)
# 观察空间类型（包含环境状态的所有信息）
Observation = TypedDict(
    'Observation', {
        # 新增发现的节点数量
        'newly_discovered_nodes_count': numpy.int32,
        # 是否成功横向移动
        'lateral_move': numpy.int32,
        # 是否发现客户数据
        'customer_data_found': Tuple[numpy.int32],
        # 探测结果（0-未尝试，1-失败，2-成功）
        'probe_result': numpy.int32,
        # 权限提升结果
        'escalation': numpy.int32,
        # 泄露的凭据列表（每个元素为[是否使用, 凭据ID, 目标节点, 端口]）
        'leaked_credentials': Tuple[numpy.ndarray, ...],
        # 当前有效动作掩码
        'action_mask': ActionMask,
        # 凭据缓存当前长度
        'credential_cache_length': int,
        # 已发现节点总数
        'discovered_node_count': int,
        # 节点属性矩阵（每个节点对应一个属性向量）
        'discovered_nodes_properties': Tuple[numpy.ndarray, ...],
        # 节点权限等级数组
        'nodes_privilegelevel': numpy.ndarray,
        # 凭据缓存矩阵（每个凭据对应[目标节点索引, 端口索引]）
        'credential_cache_matrix': Tuple[numpy.ndarray, ...],
        # 原始数据（不在Gym观察空间中的内部信息）
        '_credential_cache': List[model.CachedCredential],  # 凭据缓存内部表示
        '_discovered_nodes': List[model.NodeID],            # 已发现节点ID列表
        '_explored_network': networkx.DiGraph                # 已探索的网络图
    })


# Information returned to gym by the step function
StepInfo = TypedDict(
    'StepInfo', {
        'description': str,
        'duration_in_ms': float,
        'step_count': int,
        'network_availability': float
    })


class OutOfBoundIndexError(Exception):
    """The agent attempted to reference an entity (node or a vulnerability) with an invalid index"""


Key = TypeVar('Key')
Value = TypeVar('Value')


def inverse_dict(self: Dict[Key, Value]) -> Dict[Value, Key]:
    """Inverse a dictionary"""
    return {v: k for k, v in self.items()}


class DummySpace(spaces.Space):
    """This class ensures that the values in the gym.spaces.Dict space are derived from gym.Space"""

    def __init__(self, sample: object):
        self._sample = sample

    def contains(self, obj: object) -> bool:
        return True

    def sample(self) -> object:
        return self._sample


def sourcenode_of_action(x: Action) -> int:
    """Return the source node of a given action"""
    if 'local_vulnerability' in x:
        return x['local_vulnerability'][0]
    elif 'remote_vulnerability' in x:
        return x['remote_vulnerability'][0]

    assert 'connect' in x
    return x['connect'][0]


class EnvironmentBounds(NamedTuple):
    """定义环境资源边界
    Attributes:
        maximum_node_count: 最大节点数
        maximum_total_credentials: 最大凭据数
        port_count: 端口类型数量
        property_count: 节点属性类型数量
        local_attacks_count: 本地漏洞类型数量
        remote_attacks_count: 远程漏洞类型数量
        computation_attacks_count: 算力攻击数量
    """
    maximum_total_credentials: int
    maximum_node_count: int
    maximum_discoverable_credentials_per_action: int

    port_count: int
    property_count: int
    local_attacks_count: int
    remote_attacks_count: int
    computation_attacks_count: int

    @classmethod
    def of_identifiers(cls,
                       identifiers: model.Identifiers,
                       maximum_total_credentials: int,
                       maximum_node_count: int,
                       maximum_discoverable_credentials_per_action: Optional[int] = None
                       ):
        if not maximum_discoverable_credentials_per_action:
            maximum_discoverable_credentials_per_action = maximum_total_credentials
        return EnvironmentBounds(
            maximum_total_credentials=maximum_total_credentials,
            maximum_node_count=maximum_node_count,
            maximum_discoverable_credentials_per_action=maximum_discoverable_credentials_per_action,
            port_count=len(identifiers.ports),
            property_count=len(identifiers.properties),
            local_attacks_count=len(identifiers.local_vulnerabilities),
            remote_attacks_count=len(identifiers.remote_vulnerabilities),
            computation_attacks_count=len(identifiers.computation_vulnerabilities)
        )


class AttackerGoal(NamedTuple):
    """定义攻击者获胜需要同时满足的条件。
    如果未指定字段值，则默认目标是完全控制网络节点。
    """
    # Include goal to reach at least the specifed cumulative total reward after
    reward: float = 0.0
    # Include goal to bring the availability to lower that the specified SLA value
    low_availability: float = 1.0
    # Include goal to own at least the specified number of nodes.
    own_atleast: int = 0
    # Include goal to own at least the specified percentage of the network nodes.
    # Set to 1.0 to define goal as the ownership of all network nodes.
    own_atleast_percent: float = 1.0


class DefenderGoal(NamedTuple):
    """定义防御者获胜需要同时满足的条件。"""
    # 如果攻击者被驱逐出所有网络节点，则满足条件。
    eviction: bool


class DefenderConstraint(NamedTuple):
    """定义防御者必须始终保持的约束。"""
    maintain_sla: float

class CyberBattleEnv(gym.Env):
    """OpenAI Gym 环境接口，用于 CyberBattle 仿真。

    # 动作

        执行本地攻击:               `(source_node x local_vulnerability_to_exploit)`
        执行远程攻击命令:           `(source_node x target_node x remote_vulnerability_to_exploit)`
        连接到远程节点:             `(source_node x target_node x target_port x credential_index_from_cache)`

    # 观察

       请参见 `Observation` 类型，获取完整的观察空间描述。
       包括：
       - 发现了多少个新节点
       - 横向移动是否成功
       - 是否发现了客户数据
       - 升级尝试是否成功
       - 到目前为止发现的所有节点属性矩阵
       - 泄露的凭证列表

    # 信息
       - 动作掩码，指示当前状态下有效动作的子集

    # 终止条件

    如果攻击者达到其目标（例如，完全控制网络），
    或防御者达到其目标（例如，完全驱逐攻击者），
    或防御者的某个约束未满足（例如，SLA），则仿真结束。
    """


    metadata = {'render.modes': ['human']}
    @property
    def environment(self) -> model.Environment:
        return self.__environment

    def __reset_environment(self) -> None:
        self.__environment: model.Environment = copy.deepcopy(self.__initial_environment)
        self.__discovered_nodes: List[model.NodeID] = []
        self.__owned_nodes_indices_cache: Optional[List[int]] = None
        self.__credential_cache: List[model.CachedCredential] = []
        self.__episode_rewards: List[float] = []
        
        # 重置网络状态
        self._network_state = model.NetworkState()
        self._network_state.computation_resources = {
            "gpu": model.ComputationResource(
                id="gpu", 
                total_amount=100.0, 
                current_amount=100.0, 
                value_per_unit=0.5
            ),
            "cpu": model.ComputationResource(
                id="cpu", 
                total_amount=200.0, 
                current_amount=200.0, 
                value_per_unit=0.2
            )
        }
        self._network_state.hijacked_computation = {}
        
        # The actuator used to execute actions in the simulation environment
        self._actuator = actions.AgentActions(self.__environment, throws_on_invalid_actions=self.__throws_on_invalid_actions)
        self._defender_actuator = actions.DefenderAgentActions(self.__environment)

        self.__stepcount = 0
        self.__start_time = time.time()
        self.__done = False

        for node_id, node_data in self.__environment.nodes():
            if node_data.agent_installed:
                self.__discovered_nodes.append(node_id)

    @property
    def name(self) -> str:
        return "CyberBattleEnv"

    @property
    def identifiers(self) -> model.Identifiers:
        return self.__environment.identifiers

    @property
    def bounds(self) -> EnvironmentBounds:
        return self.__bounds

    def validate_environment(self, environment: model.Environment):
        """验证网络的大小和相关常量是否符合为CyberBattle gym环境设置的尺寸范围。"""
        assert environment.identifiers.ports
        assert environment.identifiers.properties
        assert environment.identifiers.local_vulnerabilities
        assert environment.identifiers.remote_vulnerabilities

        node_count = len(environment.network.nodes.items())
        if node_count > self.__bounds.maximum_node_count:
            raise ValueError(f"Network node count ({node_count}) exceeds "
                             f"the specified limit of {self.__bounds.maximum_node_count}.")

        # Maximum number of credentials that can possibly be returned by any action
        effective_maximum_credentials_per_action = max([
            len(vulnerability.outcome.credentials)
            for _, node_info in environment.nodes()
            for _, vulnerability in node_info.vulnerabilities.items()
            if isinstance(vulnerability.outcome, model.LeakedCredentials)])

        if effective_maximum_credentials_per_action > self.__bounds.maximum_discoverable_credentials_per_action:
            raise ValueError(
                f"Some action in the environment returns {effective_maximum_credentials_per_action} "
                f"credentials which exceeds the maximum number of discoverable credentials "
                f"of {self.__bounds.maximum_discoverable_credentials_per_action}")

        refeerenced_ports = model.collect_ports_from_environment(environment)
        undefined_ports = set(refeerenced_ports).difference(environment.identifiers.ports)
        if undefined_ports:
            raise ValueError(f"The network has references to undefined port names: {undefined_ports}")

        referenced_properties = model.collect_properties_from_nodes(model.iterate_network_nodes(environment.network))
        undefined_properties = set(referenced_properties).difference(environment.identifiers.properties)
        if undefined_properties:
            raise ValueError(f"The network has references to undefined property names: {undefined_properties}")

        local_vulnerabilities = \
            model.collect_vulnerability_ids_from_nodes_bytype(
                environment.nodes(),
                environment.vulnerability_library,
                model.VulnerabilityType.LOCAL
            )

        undefined_local_vuln = set(local_vulnerabilities).difference(environment.identifiers.local_vulnerabilities)
        if undefined_local_vuln:
            raise ValueError(f"The network has references to undefined local"
                             f" vulnerability names: {undefined_local_vuln}")

        remote_vulnerabilities = \
            model.collect_vulnerability_ids_from_nodes_bytype(
                environment.nodes(),
                environment.vulnerability_library,
                model.VulnerabilityType.REMOTE
            )

        undefined_remote_vuln = set(remote_vulnerabilities).difference(environment.identifiers.remote_vulnerabilities)
        if undefined_remote_vuln:
            raise ValueError(f"The network has references to undefined remote"
                             f" vulnerability names: {undefined_remote_vuln}")

    # number of distinct privilege levels
    privilege_levels = model.PrivilegeLevel.MAXIMUM + 1

    def __init__(self,
                 initial_environment: model.Environment,
                 maximum_total_credentials: int = 1000,
                 maximum_node_count: int = 100,
                 maximum_discoverable_credentials_per_action: int = 5,
                 defender_agent: Optional[DefenderAgent] = None,
                 attacker_goal: Optional[AttackerGoal] = AttackerGoal(own_atleast_percent=1.0),
                 defender_goal=DefenderGoal(eviction=True),
                 defender_constraint=DefenderConstraint(maintain_sla=0.0),
                 winning_reward=5000.0,
                 losing_reward=0.0,
                 renderer='',
                 observation_padding=False,
                 throws_on_invalid_actions=True,
                 ):
        """参数
        ===========
        environment               - CyberBattle 网络模拟环境
        maximum_total_credentials - 网络中使用的最大凭证总数
        maximum_node_count        - 网络的最大可能节点数
        maximum_discoverable_credentials_per_action - 每个动作返回的最大凭证数量
        attacker_goal             - 攻击者胜利并停止模拟的目标
        defender_goal             - 防御者胜利并停止模拟的目标
        defender_constraint       - 防御者必须维持的约束，以保持模拟运行
        winning_reward            - 如果模拟因攻击者达到目标而结束，攻击者将获得的奖励
        losing_reward             - 如果模拟因防御者达到目标而结束，攻击者将获得的奖励
        renderer                  - matplotlib 渲染器（例如 'png'）
        observation_padding       - 是否将所有观察字段填充到最大大小。例如，这将填充凭证矩阵以适应 `maximum_node_count` 行。对于期望固定大小观察的gym代理，启用此标志。
        throws_on_invalid_actions - 如果步骤函数尝试无效的操作（例如，从未拥有的节点发起攻击），是否引发异常。如果设置为 False，则返回负奖励。
        """

        # maximum number of entities in a given environment
        self.__bounds = EnvironmentBounds.of_identifiers(
            maximum_total_credentials=maximum_total_credentials,
            maximum_node_count=maximum_node_count,
            maximum_discoverable_credentials_per_action=maximum_discoverable_credentials_per_action,
            identifiers=initial_environment.identifiers)

        self.validate_environment(initial_environment)
        self.__attacker_goal: Optional[AttackerGoal] = attacker_goal
        self.__defender_goal: DefenderGoal = defender_goal
        self.__defender_constraint: DefenderConstraint = defender_constraint
        self.__WINNING_REWARD = winning_reward
        self.__LOSING_REWARD = losing_reward
        self.__renderer = renderer
        self.__observation_padding = observation_padding
        self.__throws_on_invalid_actions = throws_on_invalid_actions

        self.viewer = None

        self.__initial_environment: model.Environment = initial_environment
        self._network_state = model.NetworkState()

        # number of entities in the environment network
        self.__defender_agent = defender_agent

        self.__reset_environment()

        self.__node_count = len(initial_environment.network.nodes.items())

        # The Space object defining the valid actions of an attacker.
        local_vulnerabilities_count = self.__bounds.local_attacks_count
        remote_vulnerabilities_count = self.__bounds.remote_attacks_count
        computation_attacks_count = self.__bounds.computation_attacks_count
        maximum_node_count = self.__bounds.maximum_node_count
        property_count = self.__bounds.property_count
        port_count = self.__bounds.port_count

        action_spaces: ActionSpaceDict = {
            "local_vulnerability": spaces.MultiDiscrete(
                [maximum_node_count, local_vulnerabilities_count]),
            "remote_vulnerability": spaces.MultiDiscrete(
                [maximum_node_count, maximum_node_count, remote_vulnerabilities_count]),
            "connect": spaces.MultiDiscrete(
                [maximum_node_count, maximum_node_count, port_count, maximum_total_credentials]),
            "exploit_computation_leak": spaces.MultiDiscrete(
                [maximum_node_count, max(1, computation_attacks_count)])
        }

        self.action_space = DiscriminatedUnion(cast(dict, action_spaces))

        # 观察空间返回每个可能动作的结果
        self.observation_space = spaces.Dict({
            # how many new nodes were discovered
            'newly_discovered_nodes_count': spaces.Discrete(NA + maximum_node_count),
            # successuflly moved to the target node (1) or not (0)
            'lateral_move': spaces.Discrete(2),
            # boolean: 1 if customer secret data were discovered, 0 otherwise
            'customer_data_found': spaces.MultiBinary(1),
            # whether an attempted probing succeeded or not
            'probe_result': spaces.Discrete(3),
            # Esclation result
            'escalation': spaces.Discrete(model.PrivilegeLevel.MAXIMUM + 1),
            # Array of slots describing credentials that were leaked
            'leaked_credentials': spaces.Tuple(
                # the 1st component indicates if the slot is used or not (SLOT_USED or SLOT_UNSUED)
                # the 2nd component gives the credential unique index (external identifier exposed to the agent)
                # the 3rd component gives the target node ID
                # the 4th component gives the port number
                #
                #  The actual credential secret is not returned by the environment.
                #  To use the credential as a parameter to another action the agent should refer to it by its index
                #  e.g. (UNUSED_SLOT,_,_,_) encodes an empty slot
                #       (USED_SLOT,1,56,22) encodes a leaked credential identified by its index 1,
                #          that was used to authenticat to target node 56 on port number 22 (e.g. SSH)

                [spaces.MultiDiscrete([NA + 1, self.__bounds.maximum_total_credentials,
                                       maximum_node_count, port_count])]
                * self.__bounds.maximum_discoverable_credentials_per_action),

            # Boolean bitmasks defining the subset of valid actions in the current state.
            # (1 for valid, 0 for invalid). Note: a valid action is not necessariliy guaranteed to succeed.
            # For instance it is a valid action to attempt to connect to a remote node with incorrect credentials,
            # even though such action would 'fail' and potentially yield a negative reward.
            "action_mask": spaces.Dict({
                "local_vulnerability":
                    spaces.MultiBinary([maximum_node_count, local_vulnerabilities_count]),
                "remote_vulnerability":
                    spaces.MultiBinary([maximum_node_count, maximum_node_count, remote_vulnerabilities_count]),
                "connect":
                    spaces.MultiBinary([maximum_node_count, maximum_node_count, port_count, maximum_total_credentials]),
                "exploit_computation_leak":
                    spaces.MultiBinary([maximum_node_count, max(1, computation_attacks_count)])
            }),

            # size of the credential stack
            'credential_cache_length': spaces.Discrete(maximum_total_credentials),

            # total nodes discovered so far
            'discovered_node_count': spaces.Discrete(maximum_node_count),

            # Matrix of properties for all the discovered nodes
            # 3 values for each matrix cell: unset (0), set (1), unknown (2)
            'discovered_nodes_properties': spaces.Tuple([spaces.MultiDiscrete([3] * property_count)] * maximum_node_count),

            # Escalation level on every discovered node (e.g., 0 if not owned, 1 for admin, 2 for system)
            'nodes_privilegelevel': spaces.MultiDiscrete([CyberBattleEnv.privilege_levels] * maximum_node_count),

            # Encoding of the credential cache of shape: (credential_cache_length, 2)
            #
            # Each row represent a discovered credential,
            # the credential index is given by the row index (i.e. order of discovery)
            # A row is of the form: (target_node_discover_index, port_index)
            'credential_cache_matrix': spaces.Tuple(
                [spaces.MultiDiscrete([self.__bounds.maximum_node_count, self.__bounds.port_count])] * self.__bounds.maximum_total_credentials),

            # ---------------------------------------------------------
            # Fields that were previously in the 'info' dict:
            # ---------------------------------------------------------

            # internal IDs of the credentials in the cache
            '_credential_cache': DummySpace(sample=[model.CachedCredential('Sharepoint', "HTTPS", "ADPrincipalCreds")]),

            # internal IDs of nodes discovered so far
            '_discovered_nodes': DummySpace(sample=['node1', 'node0', 'node2']),

            # The subgraph of nodes discovered so far with annotated edges
            # representing interactions that took place during the simulation. (See
            # actions.EdgeAnnotation)
            '_explored_network': DummySpace(sample=networkx.DiGraph()),
        })

        # reward_range: A tuple corresponding to the min and max possible rewards
        self.reward_range = (-float('inf'), float('inf'))

    def __index_to_local_vulnerabilityid(self, vulnerability_index: int) -> model.VulnerabilityID:
        """根据内部编码索引返回本地漏洞标识符"""
        return self.__initial_environment.identifiers.local_vulnerabilities[vulnerability_index]

    def __index_to_remote_vulnerabilityid(self, vulnerability_index: int) -> model.VulnerabilityID:
        """根据内部编码索引返回远程漏洞标识符"""
        return self.__initial_environment.identifiers.remote_vulnerabilities[vulnerability_index]

    def __index_to_port_name(self, port_index: int) -> model.PortName:
        """根据内部编码索引返回端口名称标识符"""
        return self.__initial_environment.identifiers.ports[port_index]

    def __portname_to_index(self, port_name: PortName) -> int:
        """返回给定端口名称的内部编码索引"""
        return self.__initial_environment.identifiers.ports.index(port_name)

    def __internal_node_id_from_external_node_index(self, node_external_index: int) -> model.NodeID:
        """返回与指定外部节点索引对应的内部环境节点ID，该索引对Gym代理暴露
                0 -> 初始节点的ID
                1 -> 第一个发现的节点的ID
                ...
        """
        # Ensures that the specified node is known by the agent
        if node_external_index < 0:
            raise OutOfBoundIndexError(f"Node index must be positive, given {node_external_index}")

        length = len(self.__discovered_nodes)
        if node_external_index >= length:
            raise OutOfBoundIndexError(
                f"Node index ({node_external_index}) is invalid; only {length} nodes discovered so far.")

        node_id = self.__discovered_nodes[node_external_index]
        return node_id

    def __find_external_index(self, node_id: model.NodeID) -> int:
        """找到与指定节点ID关联的外部索引"""
        return self.__discovered_nodes.index(node_id)

    def __agent_owns_node(self, node_id: model.NodeID) -> bool:
        node = self.__environment.get_node(node_id)
        pwned: bool = node.agent_installed
        return pwned

    def apply_mask(self, action: Action, mask: Optional[ActionMask] = None) -> bool:
        """将动作掩码应用于特定动作。仅当该动作被允许时返回true。"""
        if mask is None:
            mask = self.compute_action_mask()
        field_name = DiscriminatedUnion.kind(action)
        field_mask, coordinates = mask[field_name], action[field_name]  # type: ignore
        return bool(field_mask[tuple(coordinates)])

    def __get_blank_action_mask(self) -> ActionMask:
        """创建一个空的动作掩码"""
        max_node_count = self.__bounds.maximum_node_count
        local_vulnerabilities_count = len(self.__initial_environment.identifiers.local_vulnerabilities)
        remote_vulnerabilities_count = len(self.__initial_environment.identifiers.remote_vulnerabilities)
        computation_vulnerabilities_count = len(self.__initial_environment.identifiers.computation_vulnerabilities)
        port_count = len(self.__initial_environment.identifiers.ports)

        local = numpy.zeros(
            shape=(max_node_count, local_vulnerabilities_count), dtype=numpy.int32)
        remote = numpy.zeros(
            shape=(max_node_count, max_node_count, remote_vulnerabilities_count), dtype=numpy.int32)
        connect = numpy.zeros(
            shape=(max_node_count, max_node_count, port_count, self.__bounds.maximum_total_credentials), dtype=numpy.int32)
        exploit_computation_leak = numpy.zeros(
            shape=(max_node_count, max(1, computation_vulnerabilities_count)),  # 使用max(1, computation_vulnerabilities_count)确保至少为1
            dtype=numpy.int32)
        
        return ActionMask(
            local_vulnerability=local,
            remote_vulnerability=remote,
            connect=connect,
            exploit_computation_leak=exploit_computation_leak
        )

    def __update_action_mask(self, bitmask: ActionMask) -> None:
        """根据当前状态更新动作掩码"""
        local_vulnerabilities_count = self.__bounds.local_attacks_count
        remote_vulnerabilities_count = self.__bounds.remote_attacks_count
        computation_vulnerabilities_count = self.__bounds.computation_attacks_count
        port_count = self.__bounds.port_count

        # Compute the vulnerability action bitmask
        #
        # The agent may attempt exploiting vulnerabilities
        # from any node that it owns
        for source_node_id in self.__discovered_nodes:
            if self.__agent_owns_node(source_node_id):
                source_index = self.__find_external_index(source_node_id)

                # 本地：由于代理拥有该节点，因此它可以看到所有本地漏洞
                for vulnerability_index in range(local_vulnerabilities_count):
                    vulnerability_id = self.__index_to_local_vulnerabilityid(vulnerability_index)
                    node_vulnerable = vulnerability_id in self.__environment.vulnerability_library or \
                        vulnerability_id in self.__environment.get_node(
                            source_node_id).vulnerabilities

                    if node_vulnerable:
                        bitmask["local_vulnerability"][source_index, vulnerability_index] = 1

                # 远程：到目前为止发现的任何其他节点都是潜在的远程目标
                for target_node_id in self.__discovered_nodes:
                    target_index = self.__find_external_index(target_node_id)
                    bitmask["remote_vulnerability"][source_index,
                                                    target_index,
                                                    :remote_vulnerabilities_count] = 1

                    # 代理可以尝试连接到任何端口
                    # 并使用其缓存中的任何凭证（尽管不能保证成功）
                    bitmask["connect"][source_index,
                                       target_index,
                                       :port_count,
                                       :len(self.__credential_cache)] = 1

                # 在已拥有的节点上允许执行算力劫持攻击
                for node_id in self.__discovered_nodes:
                    if self.__agent_owns_node(node_id):
                        node_index = self.__find_external_index(node_id)
                        # 检查节点是否有算力劫持漏洞
                        for vulnerability_index in range(computation_vulnerabilities_count):
                            vulnerability_id = self.__index_to_computation_vulnerabilityid(vulnerability_index)
                            node_vulnerable = vulnerability_id in self.__environment.vulnerability_library or \
                                vulnerability_id in self.__environment.get_node(node_id).vulnerabilities
                            
                            if node_vulnerable:
                                bitmask["exploit_computation_leak"][node_index, vulnerability_index] = 1

    def compute_action_mask(self) -> ActionMask:
        """计算当前状态下的动作掩码"""
        bitmask = self.__get_blank_action_mask()
        self.__update_action_mask(bitmask)
        return bitmask

    def pretty_print_internal_action(self, action: Action) -> str:
        """以漂亮的格式打印带有内部节点和漏洞标识符的动作"""
        assert 1 == len(action.keys())
        assert DiscriminatedUnion.kind(action) != ''
        if "local_vulnerability" in action:
            source_node_index, vulnerability_index = action['local_vulnerability']
            return f"local_vulnerability(`{self.__internal_node_id_from_external_node_index(source_node_index)}, {self.__index_to_local_vulnerabilityid(vulnerability_index)})"
        elif "remote_vulnerability" in action:
            source_node, target_node, vulnerability_index = action["remote_vulnerability"]
            source_node_id = self.__internal_node_id_from_external_node_index(source_node)
            target_node_id = self.__internal_node_id_from_external_node_index(target_node)
            return f"remote_vulnerability(`{source_node_id}, `{target_node_id}, {self.__index_to_remote_vulnerabilityid(vulnerability_index)})"
        elif "connect" in action:
            source_node, target_node, port_index, credential_cache_index = action["connect"]
            assert credential_cache_index >= 0
            if credential_cache_index >= len(self.__credential_cache):
                return "connect(invalid)"
            source_node_id = self.__internal_node_id_from_external_node_index(source_node)
            target_node_id = self.__internal_node_id_from_external_node_index(target_node)
            return f"connect(`{source_node_id}, `{target_node_id}, {self.__index_to_port_name(port_index)}, {self.__credential_cache[credential_cache_index].credential})"
        elif "exploit_computation_leak" in action:
            source_node, target_node, vulnerability_index = action["exploit_computation_leak"]
            source_node_id = self.__internal_node_id_from_external_node_index(source_node)
            target_node_id = self.__internal_node_id_from_external_node_index(target_node)
            vulnerability_id = self.__index_to_computation_vulnerabilityid(vulnerability_index)
            return f"exploit_computation_leak(`{source_node_id}, `{target_node_id}, {vulnerability_id})"
        raise ValueError("Invalid discriminated union value: " + str(action))

    def __execute_action(self, action: Action) -> actions.ActionResult:
        if "local_vulnerability" in action:
            source_node_index, vulnerability_index = action['local_vulnerability']
            return self._actuator.exploit_local_vulnerability(
                self.__internal_node_id_from_external_node_index(source_node_index),
                self.__index_to_local_vulnerabilityid(vulnerability_index))
        elif "remote_vulnerability" in action:
            source_node, target_node, vulnerability_index = action["remote_vulnerability"]
            source_node_id = self.__internal_node_id_from_external_node_index(source_node)
            target_node_id = self.__internal_node_id_from_external_node_index(target_node)

            result = self._actuator.exploit_remote_vulnerability(
                source_node_id,
                target_node_id,
                self.__index_to_remote_vulnerabilityid(vulnerability_index))

            return result
        elif "connect" in action:
            source_node, target_node, port_index, credential_cache_index = action["connect"]
            if credential_cache_index < 0 or credential_cache_index >= len(self.__credential_cache):
                return actions.ActionResult(reward=-1, outcome=None)

            source_node_id = self.__internal_node_id_from_external_node_index(source_node)
            target_node_id = self.__internal_node_id_from_external_node_index(target_node)

            result = self._actuator.connect_to_remote_machine(
                source_node_id,
                target_node_id,
                self.__index_to_port_name(port_index),
                self.__credential_cache[credential_cache_index].credential)

            return result
        elif "exploit_computation_leak" in action:
            node_index, vulnerability_index = action["exploit_computation_leak"]
            node_id = self.__internal_node_id_from_external_node_index(node_index)
            vulnerability_id = self.__index_to_computation_vulnerabilityid(vulnerability_index)
            
            LOGGER.info(f"尝试执行算力劫持漏洞: 节点={node_id}, 漏洞ID={vulnerability_id}")
            
            # 检查节点属性
            node = self.__environment.get_node(node_id)
            LOGGER.info(f"节点属性: {node.properties}")
            
            # 检查漏洞定义
            vulnerability = node.vulnerabilities.get(vulnerability_id)
            if vulnerability:
                LOGGER.info(f"漏洞信息: {vulnerability}")
            else:
                LOGGER.info(f"节点没有定义漏洞: {vulnerability_id}")
            
            return self._actuator.exploit_computation_leak_vulnerability(
                node_id,
                vulnerability_id)
        raise ValueError("Invalid discriminated union value: " + str(action))

    def __get_blank_observation(self) -> Observation:
        observation = Observation(
            newly_discovered_nodes_count=numpy.int32(0),
            leaked_credentials=tuple(
                [numpy.array([UNUSED_SLOT, 0, 0, 0], dtype=numpy.int32)]
                * self.__bounds.maximum_discoverable_credentials_per_action),
            lateral_move=numpy.int32(0),
            customer_data_found=(numpy.int32(0),),
            escalation=numpy.int32(PrivilegeLevel.NoAccess),
            action_mask=self.__get_blank_action_mask(),
            probe_result=numpy.int32(0),
            credential_cache_matrix=tuple([numpy.zeros((2))] * self.__bounds.maximum_total_credentials),
            credential_cache_length=0,
            discovered_node_count=len(self.__discovered_nodes),
            discovered_nodes_properties=tuple(
                [numpy.full((self.__bounds.property_count,), 2, dtype=numpy.int32)] * self.__bounds.maximum_node_count),

            nodes_privilegelevel=numpy.zeros((self.bounds.maximum_node_count,), dtype=numpy.int32),

            # 原始数据实际上并没有被编码为合适的gym数值空间
            # （之前是通过 'info' 字典返回的）
            _credential_cache=self.__credential_cache,
            _discovered_nodes=self.__discovered_nodes,
            _explored_network=self.__get_explored_network()
        )

        return observation

    def __pad_array_if_requested(self, o, pad_value, desired_length) -> numpy.ndarray:
        """如果为此环境启用了填充选项，则使用提供的填充对数组观察进行填充"""
        if self.__observation_padding:
            padding = numpy.full((desired_length - len(o)), pad_value, dtype=numpy.int32)
            return numpy.concatenate((o, padding))
        else:
            return o

    def __pad_tuple_if_requested(self, o, row_shape, desired_length) -> Tuple[numpy.ndarray, ...]:
        """如果为此环境启用了填充选项，则使用提供的填充对元组观察进行填充"""
        if self.__observation_padding:
            padding = [numpy.zeros(row_shape, dtype=numpy.int32)] * (desired_length - len(o))
            return tuple(o + padding)
        else:
            return tuple(o)

    def __property_vector(self, node_id: model.NodeID, node_info: model.NodeInfo) -> numpy.ndarray:
        """指定节点的属性向量
        每个单元格的值为 1 表示属性已设置，0 表示未设置，2 表示未知（节点尚未被代理拥有）"""
        properties_indices = list(self._actuator.get_discovered_properties(node_id))

        is_owned = self._actuator.get_node_privilegelevel(node_id) >= PrivilegeLevel.LocalUser

        if is_owned:
            # 如果节点已被拥有，则我们知道它的所有属性
            vector = numpy.full((self.__bounds.property_count), 0, dtype=numpy.int32)
        else:
            # 否则，我们对未发现的属性一无所知 => 0 应该是默认值
            vector = numpy.zeros((self.__bounds.property_count), dtype=numpy.int32)

        vector[properties_indices] = 1
        return vector

    def __get_property_matrix(self) -> Tuple[numpy.ndarray, ...]:
        """返回节点-属性矩阵，
        其中 0 表示该节点的属性未设置
               1 表示该节点的属性已设置
               2 表示该属性状态未知

        例如： [ 1 0 0 1 ]
                2 2 2 2
                0 1 0 1 ]
         第1行：第1个已发现且拥有的节点的设置和未设置属性
         第2行：第2个已发现的节点没有已知属性
         第3行：第3个已发现且拥有的节点的属性"""
        property_discovered = [
            self.__property_vector(node_id, node_info)
            for node_id, node_info in self._actuator.discovered_nodes()
        ]
        return self.__pad_tuple_if_requested(property_discovered, self.__bounds.property_count, self.__bounds.maximum_node_count)

    def __get__owned_nodes_indices(self) -> List[int]:
        """获取所有已拥有节点的索引列表"""
        if self.__owned_nodes_indices_cache is None:
            owned_nodeids = self._actuator.get_nodes_with_atleast_privilegelevel(PrivilegeLevel.LocalUser)
            self.__owned_nodes_indices_cache = [self.__find_external_index(n) for n in owned_nodeids]

        return self.__owned_nodes_indices_cache

    def __get_privilegelevel_array(self) -> numpy.ndarray:
        """返回节点升级级别数组，
        其中 0 表示节点未被拥有
               1 表示节点已被拥有
               2 表示节点已被拥有并提升为管理员
               3 表示节点已被拥有并提升为系统级别
               ... 网络定义的进一步升级级别
        """
        privilegelevel_array = numpy.array([
            int(self._actuator.get_node_privilegelevel(node))
            for node in self.__discovered_nodes], dtype=numpy.int32)

        return self.__pad_array_if_requested(privilegelevel_array, PrivilegeLevel.NoAccess, self.__bounds.maximum_node_count)

    def __observation_reward_from_action_result(self, result: actions.ActionResult) -> Tuple[Observation, float]:
        obs = self.__get_blank_observation()
        outcome = result.outcome

        if isinstance(outcome, model.LeakedNodesId):
            # 更新已发现的节点
            newly_discovered_nodes_count = 0
            for node in outcome.nodes:
                if node not in self.__discovered_nodes:
                    self.__discovered_nodes.append(node)
                    newly_discovered_nodes_count += 1

            obs['newly_discovered_nodes_count'] = numpy.int32(newly_discovered_nodes_count)

        elif isinstance(outcome, model.LeakedCredentials):
            # 更新已发现的节点和凭证
            newly_discovered_nodes_count = 0
            newly_discovered_creds: List[Tuple[int, model.CachedCredential]] = []
            for cached_credential in outcome.credentials:
                if cached_credential.node not in self.__discovered_nodes:
                    self.__discovered_nodes.append(cached_credential.node)
                    newly_discovered_nodes_count += 1

                if cached_credential not in self.__credential_cache:
                    self.__credential_cache.append(cached_credential)
                    added_credential_index = len(self.__credential_cache) - 1
                    newly_discovered_creds.append((added_credential_index, cached_credential))

            obs['newly_discovered_nodes_count'] = numpy.int32(newly_discovered_nodes_count)

            # 将返回的凭证编码为gym代理预期的格式
            leaked_credentials = [numpy.array([USED_SLOT,
                                               cache_index,
                                               self.__find_external_index(cached_credential.node),
                                               self.__portname_to_index(cached_credential.port)], numpy.int32)
                                  for cache_index, cached_credential in newly_discovered_creds]

            obs['leaked_credentials'] = self.__pad_tuple_if_requested(leaked_credentials, 4, self.__bounds.maximum_discoverable_credentials_per_action)

        elif isinstance(outcome, model.LateralMove):
            obs['lateral_move'] = numpy.int32(1)
        elif isinstance(outcome, model.CustomerData):
            obs['customer_data_found'] = (numpy.int32(1),)
        elif isinstance(outcome, model.ProbeSucceeded):
            obs['probe_result'] = numpy.int32(2)
        elif isinstance(outcome, model.ProbeFailed):
            obs['probe_result'] = numpy.int32(1)
        elif isinstance(outcome, model.PrivilegeEscalation):
            obs['escalation'] = numpy.int32(outcome.level)

        cache = [numpy.array([self.__find_external_index(c.node), self.__portname_to_index(c.port)])
                 for c in self.__credential_cache]

        obs['credential_cache_matrix'] = self.__pad_tuple_if_requested(cache, 2, self.__bounds.maximum_total_credentials)

        # Dynamic statistics to be refreshed
        obs['credential_cache_length'] = len(self.__credential_cache)
        obs['discovered_node_count'] = len(self.__discovered_nodes)
        obs['discovered_nodes_properties'] = self.__get_property_matrix()
        obs['nodes_privilegelevel'] = self.__get_privilegelevel_array()
        obs['_credential_cache'] = self.__credential_cache
        obs['_discovered_nodes'] = self.__discovered_nodes
        obs['_explored_network'] = self.__get_explored_network()

        self.__update_action_mask(obs['action_mask'])

        observation = {
            **obs,
            "hijacked_computation": self._network_state.hijacked_computation.copy()
        }

        return observation, result.reward

    def sample_connect_action_in_expected_range(self) -> Action:
        """抽取一种"连接"类型的动作，其中参数在预期范围内，但不一定验证组件之间的约束。"""
        np_random = self.action_space.np_random
        discovered_credential_count = len(self.__credential_cache)

        if discovered_credential_count <= 0:
            raise ValueError("Cannot sample a connect action until the agent discovers more potential target nodes.")

        return Action(connect=numpy.array([
            np_random.choice(self.__get__owned_nodes_indices()),
            np_random.randint(len(self.__discovered_nodes)),
            np_random.randint(self.__bounds.port_count),
            # credential space is sparse so we force sampling
            # from the set of credentials that were discovered so far
            np_random.randint(len(self.__credential_cache))], numpy.int32))

    def sample_action_in_range(self, kinds: Optional[List[int]] = None) -> Action:
        """在预期的组件范围内抽取一个动作，但不一定验证组件之间的约束。
        （例如，可能返回一个不被节点支持的 local_vulnerability 动作）

        - kinds -- 一个包含 {0,1,2} 元素的列表，表示要抽取的动作类型（0：本地，1：远程，2：连接）"""
        np_random = self.action_space.np_random

        discovered_credential_count = len(self.__credential_cache)

        if kinds is None:
            kinds = [0, 1, 2]

        if discovered_credential_count == 0:
            # cannot generate a connect action if no cred in the cache
            kinds = [t for t in kinds if t != 2]

        assert kinds, 'Kinds list cannot be empty'

        kind = np_random.choice(kinds)

        if kind == 2:
            action = self.sample_connect_action_in_expected_range()
        elif kind == 1:
            action = Action(local_vulnerability=numpy.array([
                np_random.choice(self.__get__owned_nodes_indices()),
                np_random.randint(self.__bounds.local_attacks_count)], numpy.int32))
        else:
            action = Action(remote_vulnerability=numpy.array([
                np_random.choice(self.__get__owned_nodes_indices()),
                np_random.randint(len(self.__discovered_nodes)),
                np_random.randint(self.__bounds.remote_attacks_count)], numpy.int32))

        return action

    def is_node_owned(self, node: int):
        """如果一个已发现的节点（通过其外部节点索引指定）被攻击者代理拥有，则返回 true"""
        node_id = self.__internal_node_id_from_external_node_index(node)
        node_owned = self._actuator.get_node_privilegelevel(node_id) > PrivilegeLevel.NoAccess
        return node_owned

    def is_action_valid(self, action, action_mask: Optional[ActionMask] = None) -> bool:
        """确定一个动作是否有效（即参数是否在预期范围内）"""
        assert 1 == len(action.keys())

        kind = DiscriminatedUnion.kind(action)
        in_range = False
        n_discovered_nodes = len(self.__discovered_nodes)
        if kind == "local_vulnerability":
            source_node, vulnerability_index = action['local_vulnerability']
            in_range = source_node < n_discovered_nodes \
                and self.is_node_owned(source_node) \
                and vulnerability_index < self.__bounds.local_attacks_count
        elif kind == "remote_vulnerability":
            source_node, target_node, vulnerability_index = action["remote_vulnerability"]
            in_range = source_node < n_discovered_nodes \
                and self.is_node_owned(source_node) \
                and target_node < n_discovered_nodes \
                and vulnerability_index < self.__bounds.remote_attacks_count
        elif kind == "connect":
            source_node, target_node, port_index, credential_cache_index = action["connect"]
            in_range = source_node < n_discovered_nodes and \
                self.is_node_owned(source_node) \
                and target_node < n_discovered_nodes \
                and port_index < self.__bounds.port_count \
                and credential_cache_index < len(self.__credential_cache)
        elif kind == "exploit_computation_leak":
            node, vulnerability_index = action["exploit_computation_leak"]
            in_range = node < n_discovered_nodes \
                and self.is_node_owned(node) \
                and vulnerability_index < self.__bounds.computation_attacks_count

        return in_range and self.apply_mask(action, action_mask)

    def sample_valid_action(self) -> Action:
        """采样一个有效的动作"""
        action_mask = self.compute_action_mask()
        
        # 获取所有可能的动作类型
        possible_actions = []
        
        # 检查本地漏洞
        if action_mask["local_vulnerability"].any():
            possible_actions.append("local_vulnerability")
        
        # 检查远程漏洞
        if action_mask["remote_vulnerability"].any():
            possible_actions.append("remote_vulnerability")
        
        # 检查连接动作
        if action_mask["connect"].any():
            possible_actions.append("connect")
        
        # 检查算力劫持漏洞
        if action_mask["exploit_computation_leak"].any():
            possible_actions.append("exploit_computation_leak")
        
        if not possible_actions:
            raise ValueError("没有有效的动作可供选择")
        
        # 随机选择一个动作类型
        action_type = numpy.random.choice(possible_actions)
        
        # 根据动作类型生成具体动作
        if action_type == "local_vulnerability":
            # 找到所有有效的本地漏洞动作
            valid_indices = numpy.where(action_mask["local_vulnerability"])
            idx = numpy.random.randint(len(valid_indices[0]))
            return Action(local_vulnerability=numpy.array([
                valid_indices[0][idx],
                valid_indices[1][idx]
            ], dtype=numpy.int32))
        
        elif action_type == "remote_vulnerability":
            # 找到所有有效的远程漏洞动作
            valid_indices = numpy.where(action_mask["remote_vulnerability"])
            idx = numpy.random.randint(len(valid_indices[0]))
            return Action(remote_vulnerability=numpy.array([
                valid_indices[0][idx],
                valid_indices[1][idx],
                valid_indices[2][idx]
            ], dtype=numpy.int32))
        
        elif action_type == "connect":
            # 找到所有有效的连接动作
            valid_indices = numpy.where(action_mask["connect"])
            idx = numpy.random.randint(len(valid_indices[0]))
            return Action(connect=numpy.array([
                valid_indices[0][idx],
                valid_indices[1][idx],
                valid_indices[2][idx],
                valid_indices[3][idx]
            ], dtype=numpy.int32))
        
        else:  # exploit_computation_leak
            # 找到所有有效的算力劫持动作
            valid_indices = numpy.where(action_mask["exploit_computation_leak"])
            idx = numpy.random.randint(len(valid_indices[0]))
            return Action(exploit_computation_leak=numpy.array([
                valid_indices[0][idx],
                valid_indices[1][idx]
            ], dtype=numpy.int32))

    def sample_valid_action_with_luck(self) -> Action:
        """抽取一个动作，直到获得一个有效的动作"""
        action_mask = self.compute_action_mask()
        action = cast(Action, self.action_space.sample())
        while not self.apply_mask(action, action_mask):
            action = cast(Action, self.action_space.sample())
        return action

    def __get_explored_network(self) -> networkx.DiGraph:
        """返回到目前为止发现的节点图，
        边上标注了表示模拟过程中发生的交互。"""
        known_nodes = [node_id for node_id, _ in self._actuator.discovered_nodes()]
        network = self.__environment.network
        subgraph = network.subgraph(known_nodes).copy()

        # hide info for nodes that the agent does not own
        for node_id in subgraph.nodes:
            node_info: Optional[model.NodeInfo] = subgraph.nodes[node_id]['data']
            if node_info is not None:
                if not node_info.agent_installed:
                    subgraph.nodes[node_id]['data'] = None

                subgraph.nodes[node_id]['privilege_level'] = int(self._actuator.get_node_privilegelevel(node_id))
                subgraph.nodes[node_id]['flags'] = list(self._actuator.get_discovered_properties(node_id))
                subgraph.nodes[node_id]['flags_bits'] = self.__property_vector(node_id, node_info)

        return subgraph

    def __attacker_goal_reached(self) -> bool:
        goal = self.__attacker_goal

        if not goal:
            return False

        if numpy.sum(self.__episode_rewards) < goal.reward:
            return False

        nodes_owned = self.__get__owned_nodes_indices()
        owned_count = len(nodes_owned)

        if owned_count < goal.own_atleast:
            return False

        if owned_count / self.__node_count < goal.own_atleast_percent:
            return False

        if self.__defender_agent is not None and \
                self._defender_actuator.network_availability >= goal.low_availability:
            return False

        return True

    def __defender_constraints_broken(self) -> bool:
        """"检查防御者的任何约束是否未满足"""
        constraint = self.__defender_constraint

        if self.__defender_agent is not None and \
                self._defender_actuator.network_availability < constraint.maintain_sla:
            return True

        return False

    def __defender_goal_reached(self) -> bool:
        """检查防御者的目标是否已达成（例如，完全驱逐攻击者）"""
        goal = self.__defender_goal

        return goal.eviction and not (self.__get__owned_nodes_indices())

    def get_explored_network_as_numpy(self, observation: Observation) -> numpy.ndarray:
        """返回已探索网络图的邻接矩阵，
        以 numpy 数组的形式，形状为 (N,N)，其中
        N 是到目前为止发现的节点数量"""
        return convert_matrix.to_numpy_array(observation['_explored_network'], weight='kind_as_float')

    def get_explored_network_node_properties_bitmap_as_numpy(self, observation: Observation) -> numpy.ndarray:
        """返回组合的邻接矩阵（左部分）和节点属性位图（右部分）。
        假设 N 是已发现节点的数量，P 是属性的总数，则
        返回的矩阵形式如下：

          ^  <---- N -----><------  P ------>
          |  (            |                 )
          N  ( 邻接矩阵    | 节点属性位图     )
          |  (            |                 )
          V  (            |                 )
        """
        return numpy.block([convert_matrix.to_numpy_array(observation['_explored_network'], weight='kind_as_float'),
                            numpy.array(observation['discovered_nodes_properties'])])

    def step(self, action: Action) -> Tuple[Observation, float, bool, StepInfo]:
        """执行一个动作并返回结果。

        Returns:
            observation: 新的观察结果
            reward: 获得的奖励
            done: 是否结束
            info: 额外信息
        """
        if self.__done:
            raise RuntimeError("new episode must be started with env.reset()")

        self.__stepcount += 1
        duration = time.time() - self.__start_time
        try:
            result = self.__execute_action(action)
            observation, reward = self.__observation_reward_from_action_result(result)

            # 计算被劫持算力资源带来的额外奖励
            computation_reward = 0.0
            for resource_id, hijacked_amount in self._network_state.hijacked_computation.items():
                # 每单位算力资源增加10点奖励
                computation_reward += hijacked_amount * 10.0
            
            # 将算力奖励添加到总奖励中
            reward += computation_reward
            
            # 更新累计奖励
            self.__episode_rewards.append(reward)
            
            # 检查是否达到目标
            done = self.__attacker_goal_reached()
            
            # 如果达到目标，添加获胜奖励
            if done and not self.__done:
                reward += self.__WINNING_REWARD
                LOGGER.info("攻击者达到目标！")
            
            # 检查防御者约束是否被违反
            defender_constraints_broken = self.__defender_constraints_broken()
            
            # 如果防御者约束被违反，添加失败惩罚
            if defender_constraints_broken and not self.__done:
                reward += self.__LOSING_REWARD
                done = True
                LOGGER.info("防御者约束被违反！")
            
            # 检查防御者是否达到目标
            defender_goal_reached = self.__defender_goal_reached()
            
            # 如果防御者达到目标，添加失败惩罚
            if defender_goal_reached and not self.__done:
                reward += self.__LOSING_REWARD
                done = True
                LOGGER.info("防御者达到目标！")
            
            self.__done = done or defender_constraints_broken or defender_goal_reached
            
            # 更新防御者状态
            if self.__defender_agent:
                self.__defender_agent.on_attacker_step()
            
            # 更新步数
            self.__stepcount += 1
            
            info = {
                'step': self.__stepcount,
                'time': time.time() - self.__start_time,
                'defender_goal_reached': defender_goal_reached,
                'defender_constraints_broken': defender_constraints_broken,
                'attacker_goal_reached': done and not (defender_goal_reached or defender_constraints_broken),
                'hijacked_computation': self._network_state.hijacked_computation,  # 添加被劫持的算力信息到info中
                'computation_reward': computation_reward  # 添加算力带来的奖励信息
            }
            
            return observation, reward, self.__done, info

        except OutOfBoundIndexError as error:
            logging.warning('Invalid entity index: ' + error.__str__())
            observation = self.__get_blank_observation()
            reward = 0.

        info = StepInfo(
            description='CyberBattle simulation',
            duration_in_ms=duration,
            step_count=self.__stepcount,
            network_availability=self._defender_actuator.network_availability)
        self.__episode_rewards.append(reward)

        return observation, reward, self.__done, info

    def reset(self) -> Observation:
        LOGGER.info("Resetting the CyberBattle environment")
        self.__reset_environment()
        observation = self.__get_blank_observation()
        observation['action_mask'] = self.compute_action_mask()
        observation['discovered_nodes_properties'] = self.__get_property_matrix()
        observation['nodes_privilegelevel'] = self.__get_privilegelevel_array()
        self.__owned_nodes_indices_cache = None
        
        # 不需要在这里重复初始化，因为已经在 __reset_environment 中完成了
        return observation

    def render_as_fig(self):
        """返回环境的可视化图表"""
        debug = EnvironmentDebugging(self._actuator)
        self._actuator.print_all_attacks()

        # 只显示网络图，不显示累计奖励
        fig = go.Figure()
        traces, layout = debug.network_as_plotly_traces()
        for t in traces:
            fig.add_trace(t)
        fig.update_layout(layout)
        return fig

    def render(self, mode: str = 'human') -> None:
        fig = self.render_as_fig()
        fig.show(renderer=self.__renderer)

    def seed(self, seed: Optional[int] = None) -> None:
        if seed is None:
            self._seed = seed
            return

        self.np_random, seed = seeding.np_random(seed)

    def close(self) -> None:
        return None

    def __index_to_computation_vulnerabilityid(self, vulnerability_index: int) -> model.VulnerabilityID:
        """根据内部编码索引返回算力劫持漏洞标识符"""
        return self.__initial_environment.identifiers.computation_vulnerabilities[vulnerability_index]
