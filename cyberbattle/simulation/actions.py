# SpiderSim - A Network Attack Simulation Environment
# Copyright (c) 2024 NRT

# This project includes code modified from CyberBattle 
# (https://github.com/microsoft/CyberBattleSim/tree/main/cyberbattle) used under Licensed under the MIT License.


"""
actions.py
这个文件包含了AgentActions类及其相关方法，该类直接与环境进行交互。它是用户和强化学习（RL）代理应当操作环境的类。
"""

from dataclasses import dataclass
import dataclasses
import datetime
from boolean import boolean
from collections import OrderedDict
import logging
from enum import Enum
from typing import (
    Iterator,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    Dict,
    TypedDict,
    cast,
)
from IPython.display import display
import pandas as pd
import random

from cyberbattle.simulation.model import (
    FirewallRule,
    MachineStatus,
    PrivilegeLevel,
    PropertyName,
    VulnerabilityID,
    VulnerabilityType,
)
from . import model


logger = logging.getLogger(__name__)
Reward = float

DiscoveredNodeInfo = TypedDict("DiscoveredNodeInfo", {"id": model.NodeID, "status": str})


class Penalty:
    """模拟中某些操作所返回的惩罚（负奖励）"""

    # 对一般可疑行为的惩罚
    SUPSPICIOUSNESS = -5.0

    # 尝试连接未开放的端口时的惩罚
    SCANNING_UNOPEN_PORT = -10.0

    # 重复尝试相同漏洞攻击时的惩罚
    REPEAT = -1

    LOCAL_EXPLOIT_FAILED = -20
    FAILED_REMOTE_EXPLOIT = -50

    # 尝试连接或在不处于运行状态的节点上执行操作时的惩罚
    MACHINE_NOT_RUNNING = 0

    # 尝试使用无效密码连接的惩罚
    WRONG_PASSWORD = -10

    # 被本地防火墙的出站规则阻挡的流量
    BLOCKED_BY_LOCAL_FIREWALL = -10

    # 被远程防火墙的入站规则阻挡的流量
    BLOCKED_BY_REMOTE_FIREWALL = -10

    # 无效操作的惩罚（例如，在没有所有权的节点上运行攻击）
    # （仅当`throws_on_invalid_actions`设置为False时使用）
    INVALID_ACTION = -1

    COMPUTATION_EXPLOIT_FAILED = -30  # 添加算力劫持失败的专门惩罚


# 第一次成功执行本地或远程攻击时的奖励
# 注意：攻击成本从此奖励中扣除。
NEW_SUCCESSFULL_ATTACK_REWARD = 70

# 发现新节点的固定奖励
NODE_DISCOVERED_REWARD = 50

# 发现新凭证的固定奖励
CREDENTIAL_DISCOVERED_REWARD = 30

# 发现新节点属性的固定奖励
PROPERTY_DISCOVERED_REWARD = 20


class EdgeAnnotation(Enum):
    """图中边的注释类型"""
    KNOWS = 0                  # 知道目标节点的凭证
    REMOTE_EXPLOIT = 1         # 远程漏洞利用
    LOCAL_EXPLOIT = 2          # 本地漏洞利用
    LATERAL_MOVE = 3          # 横向移动
    CONNECT = 4               # 节点连接
    COMPUTATION_EXPLOIT = 5    # 算力劫持攻击类型


class ActionResult(NamedTuple):
    """执行一个操作后的结果"""

    reward: Reward
    outcome: Optional[model.VulnerabilityOutcome]


ALGEBRA = boolean.BooleanAlgebra()


class OperationType(Enum):
    """定义操作类型"""
    LOCAL = "local"
    REMOTE = "remote"
    COMPUTATION = "computation"  # 算力操作类型


@dataclass
class NodeTrackingInformation:
    """跟踪模拟过程中收集的节点信息"""

    # 映射(vulnid, operation_type)到最后一次攻击的时间
    last_attack: Dict[Tuple[model.VulnerabilityID, OperationType], datetime.datetime] = dataclasses.field(default_factory=dict)
    last_owned_at: Optional[datetime.datetime] = None
    discovered_properties: Set[int] = dataclasses.field(default_factory=set)


class AgentActions:
    """
    这是AgentActions类。它与环境进行交互并对其进行修改。
    """

    def __init__(self, environment: model.Environment, throws_on_invalid_actions=True):
        """
            AgentActions 构造函数

        environment               - CyberBattleSim 环境参数
        throws_on_invalid_actions - 执行无效操作时是否抛出异常（例如，在没有所有权的节点上运行攻击）
                                    如果设置为False，则会返回负奖励。

        """
        self._environment = environment
        self._network_state = environment.network_state
        self._gathered_credentials: Set[model.CredentialID] = set()
        self._discovered_nodes: "OrderedDict[model.NodeID, NodeTrackingInformation]" = OrderedDict()
        self._throws_on_invalid_actions = throws_on_invalid_actions

        # 所有标记表明已在节点上达到某个特权级别的特殊标签列表
        self.privilege_tags = [model.PrivilegeEscalation(p).tag for p in list(PrivilegeLevel)]

        # 将所有拥有的节点标记为已发现
        for i, node in environment.nodes():
            if node.agent_installed:
                self.__mark_node_as_owned(i, PrivilegeLevel.LocalUser)

    def discovered_nodes(self) -> Iterator[Tuple[model.NodeID, model.NodeInfo]]:
        for node_id in self._discovered_nodes:
            yield (node_id, self._environment.get_node(node_id))

    def _check_prerequisites(self, target: model.NodeID, vulnerability: model.VulnerabilityInfo) -> bool:
        """
        这是一个快速的辅助函数，用于检查先决条件是否与提供的条件匹配。
        """
        node: model.NodeInfo = self._environment.network.nodes[target]["data"]
        node_flags = node.properties
        expr = vulnerability.precondition.expression

        true_value = ALGEBRA.parse("true")
        false_value = ALGEBRA.parse("false")
        mapping = {i: true_value if str(i) in node_flags else false_value for i in expr.get_symbols()}
        is_true: bool = cast(boolean.Expression, expr.subs(mapping)).simplify() == true_value
        return is_true
    def list_vulnerabilities_in_target(
        self,
        target: model.NodeID,
        type_filter: Optional[model.VulnerabilityType] = None,
    ) -> List[model.VulnerabilityID]:
        """
        此函数接受一个目标节点的model.NodeID并返回一个漏洞ID列表。
        它检查库中每个漏洞是否与给定节点的属性匹配，
        并确定该节点具有哪些漏洞。
        """
        if not self._environment.network.has_node(target):
            raise ValueError(f"无效的节点ID '{target}'")

        target_node_data: model.NodeInfo = self._environment.get_node(target)

        global_vuln: Set[model.VulnerabilityID] = {
            vuln_id
            for vuln_id, vulnerability in self._environment.vulnerability_library.items()
            if (type_filter is None or vulnerability.type == type_filter) and self._check_prerequisites(target, vulnerability)
        }

        local_vuln: Set[model.VulnerabilityID] = {
            vuln_id
            for vuln_id, vulnerability in target_node_data.vulnerabilities.items()
            if (type_filter is None or vulnerability.type == type_filter) and self._check_prerequisites(target, vulnerability)
        }

        return list(global_vuln.union(local_vuln))

    def __annotate_edge(
        self,
        source_node_id: model.NodeID,
        target_node_id: model.NodeID,
        new_annotation: EdgeAnnotation,
    ) -> None:
        """如果边不存在，则创建边，并用现有注释和指定的新注释的最大值进行注释"""
        edge_annotation = self._environment.network.get_edge_data(source_node_id, target_node_id)
        if edge_annotation is not None:
            if "kind" in edge_annotation:
                new_annotation = EdgeAnnotation(max(edge_annotation["kind"].value, new_annotation.value))
            else:
                new_annotation = EdgeAnnotation(new_annotation.value)
        self._environment.network.add_edge(
            source_node_id,
            target_node_id,
            kind=new_annotation,
            kind_as_float=float(new_annotation.value),
        )

    def get_discovered_properties(self, node_id: model.NodeID) -> Set[int]:
        return self._discovered_nodes[node_id].discovered_properties

    def __mark_node_as_discovered(self, node_id: model.NodeID) -> bool:
        logger.info("发现节点: " + node_id)
        newly_discovered = node_id not in self._discovered_nodes
        if newly_discovered:
            self._discovered_nodes[node_id] = NodeTrackingInformation()
        return newly_discovered

    def __mark_nodeproperties_as_discovered(self, node_id: model.NodeID, properties: List[PropertyName]):
        properties_indices = [self._environment.identifiers.properties.index(p) for p in properties if p not in self.privilege_tags]

        if node_id in self._discovered_nodes:
            before_count = len(self._discovered_nodes[node_id].discovered_properties)
            self._discovered_nodes[node_id].discovered_properties = self._discovered_nodes[node_id].discovered_properties.union(properties_indices)
        else:
            before_count = 0
            self._discovered_nodes[node_id] = NodeTrackingInformation(discovered_properties=set(properties_indices))

        newly_discovered_properties = len(self._discovered_nodes[node_id].discovered_properties) - before_count
        return newly_discovered_properties

    def __mark_allnodeproperties_as_discovered(self, node_id: model.NodeID):
        node_info: model.NodeInfo = self._environment.network.nodes[node_id]["data"]
        return self.__mark_nodeproperties_as_discovered(node_id, node_info.properties)

    def __mark_node_as_owned(
        self,
        node_id: model.NodeID,
        privilege: PrivilegeLevel = model.PrivilegeLevel.LocalUser,
    ) -> Tuple[Optional[datetime.datetime], bool]:
        """将节点标记为已拥有。
        返回之前的拥有时间（或None）以及是否已拥有。
        """
        node_info = self._environment.get_node(node_id)

        last_owned_at, is_currently_owned = self.__is_node_owned_history(node_id, node_info)

        if not is_currently_owned:
            if node_id not in self._discovered_nodes:
                self._discovered_nodes[node_id] = NodeTrackingInformation()
            node_info.agent_installed = True
            node_info.privilege_level = model.escalate(node_info.privilege_level, privilege)
            self._environment.network.nodes[node_id].update({"data": node_info})

            self.__mark_allnodeproperties_as_discovered(node_id)

            # 记录当前节点刚刚被占领的时间
            self._discovered_nodes[node_id].last_owned_at = datetime.datetime.now()

        return last_owned_at, is_currently_owned

    def __mark_discovered_entities(self, reference_node: model.NodeID, outcome: model.VulnerabilityOutcome) -> Tuple[int, float, int]:
        """处理漏洞利用的结果，更新已发现的实体
        
        Returns:
            Tuple[新发现的节点数, 新发现节点的价值, 新发现的凭证数]
        """
        newly_discovered_nodes = 0
        discovered_nodes_value = 0
        newly_discovered_credentials = 0

        if isinstance(outcome, model.LeakedCredentials):
            for credential in outcome.credentials:
                if credential.node not in self._discovered_nodes:
                    self._discovered_nodes[credential.node] = NodeTrackingInformation()
                    newly_discovered_nodes += 1
                    discovered_nodes_value += self._environment.get_node(credential.node).value

                if credential.credential not in self._gathered_credentials:
                    newly_discovered_credentials += 1
                    self._gathered_credentials.add(credential.credential)

                logger.info("发现凭证: " + str(credential))
                self.__annotate_edge(reference_node, credential.node, EdgeAnnotation.KNOWS)

        elif isinstance(outcome, model.LeakedNodesId):
            for node_id in outcome.nodes:
                if node_id not in self._discovered_nodes:
                    self._discovered_nodes[node_id] = NodeTrackingInformation()
                    newly_discovered_nodes += 1
                    discovered_nodes_value += self._environment.get_node(node_id).value

                logger.info("发现节点: " + str(node_id))

        elif isinstance(outcome, model.ComputationResourcesLeaked):
            logger.info(f"成功劫持算力资源: {outcome.computation_resources}")

        return newly_discovered_nodes, discovered_nodes_value, newly_discovered_credentials

    def get_node_privilegelevel(self, node_id: model.NodeID) -> model.PrivilegeLevel:
        """返回指定节点的最后记录的特权级别"""
        node_info = self._environment.get_node(node_id)
        return node_info.privilege_level

    def get_nodes_with_atleast_privilegelevel(self, level: PrivilegeLevel) -> List[model.NodeID]:
        """返回所有至少具有指定特权级别的节点"""
        return [n for n, info in self._environment.nodes() if info.privilege_level >= level]

    def is_node_discovered(self, node_id: model.NodeID) -> bool:
        """如果之前的操作已揭示指定的节点ID，返回True"""
        return node_id in self._discovered_nodes

    def __process_outcome(
        self,
        expected_type: model.VulnerabilityType,
        vulnerability_id: model.VulnerabilityID,
        node_id: model.NodeID,
        node_info: model.NodeInfo,
        operation_type: OperationType,  # 使用新的操作类型参数
        failed_penalty: float,
        throw_if_vulnerability_not_present: bool,
    ) -> Tuple[bool, ActionResult]:
        # 检查机器状态
        if node_info.status != model.MachineStatus.Running:
            logger.info("目标机器未处于运行状态")
            return False, ActionResult(reward=Penalty.MACHINE_NOT_RUNNING, outcome=None)

        is_global_vulnerability = vulnerability_id in self._environment.vulnerability_library
        is_inplace_vulnerability = vulnerability_id in node_info.vulnerabilities

        if is_global_vulnerability:
            vulnerabilities = self._environment.vulnerability_library
        elif is_inplace_vulnerability:
            vulnerabilities = node_info.vulnerabilities
        else:
            if throw_if_vulnerability_not_present:
                raise ValueError(f"漏洞 '{vulnerability_id}' 不支持节点='{node_id}'")
            else:
                logger.info(f"漏洞 '{vulnerability_id}' 不支持节点 '{node_id}'")
                return False, ActionResult(reward=Penalty.SUPSPICIOUSNESS, outcome=None)

        vulnerability = vulnerabilities[vulnerability_id]
        outcome = vulnerability.outcome

        # 验证漏洞类型
        if vulnerability.type != expected_type:
            raise ValueError(f"漏洞ID '{vulnerability_id}' 对应的攻击类型为 {vulnerability.type}，预期类型为: {expected_type}")

        # 检查漏洞先决条件
        if not self._check_prerequisites(node_id, vulnerability):
            return False, ActionResult(reward=failed_penalty, outcome=model.ExploitFailed())

        reward = 0

        # 如果漏洞类型是特权升级
        # 且该节点的升级级别尚未达到，
        # 则将升级标签添加到节点属性中
        if isinstance(outcome, model.PrivilegeEscalation):
            if outcome.tag in node_info.properties:
                return False, ActionResult(reward=Penalty.REPEAT, outcome=outcome)

            last_owned_at, is_currently_owned = self.__mark_node_as_owned(node_id, outcome.level)

            if not last_owned_at:
                reward += float(node_info.value)

            node_info.properties.append(outcome.tag)

        elif isinstance(outcome, model.LateralMove):
            last_owned_at, is_currently_owned = self.__mark_node_as_owned(node_id)

            if not last_owned_at:
                reward += float(node_info.value)

        elif isinstance(outcome, model.ProbeSucceeded):
            for p in outcome.discovered_properties:
                assert p in node_info.properties, f"发现的属性 {p} 必须属于节点的属性集。"

            newly_discovered_properties = self.__mark_nodeproperties_as_discovered(node_id, outcome.discovered_properties)
            reward += newly_discovered_properties * PROPERTY_DISCOVERED_REWARD

        # 添加对算力泄露类型的处理
        elif isinstance(outcome, model.ComputationResourcesLeaked):
            # 获取随机成功概率
            if random.random() < 0.8:  # 80% 成功率
                for resource_id in outcome.computation_resources:
                    network_state = self._network_state  # 注意访问网络状态的正确方式
                    if resource_id in network_state.computation_resources:
                        resource = network_state.computation_resources[resource_id]
                        
                        # 计算劫持的算力量
                        hijack_amount = min(outcome.amount, resource.current_amount)
                        if hijack_amount <= 0:
                            continue
                            
                        # 更新资源状态
                        resource.current_amount -= hijack_amount
                        
                        # 记录被劫持的资源
                        if resource_id in network_state.hijacked_computation:
                            network_state.hijacked_computation[resource_id] += hijack_amount
                        else:
                            network_state.hijacked_computation[resource_id] = hijack_amount
                            
                        # 计算奖励
                        additional_reward = hijack_amount * resource.value_per_unit
                        reward += additional_reward
                        
                        logger.info(f"成功劫持 {hijack_amount} 单位的 {resource_id} 算力资源")
            else:
                # 劫持失败
                logger.info("算力劫持尝试失败")
                return False, ActionResult(reward=failed_penalty, outcome=model.ExploitFailed())

        if node_id not in self._discovered_nodes:
            self._discovered_nodes[node_id] = NodeTrackingInformation()

        lookup_key = (vulnerability_id, operation_type)
        already_executed = lookup_key in self._discovered_nodes[node_id].last_attack

        if already_executed:
            last_time = self._discovered_nodes[node_id].last_attack[lookup_key]
            if node_info.last_reimaging is None or last_time >= node_info.last_reimaging:
                reward += Penalty.REPEAT
        else:
            reward += NEW_SUCCESSFULL_ATTACK_REWARD

        self._discovered_nodes[node_id].last_attack[lookup_key] = datetime.datetime.now()

        (
            newly_discovered_nodes,
            discovered_nodes_value,
            newly_discovered_credentials,
        ) = self.__mark_discovered_entities(node_id, outcome)

        # 注意: `discovered_nodes_value` 不应添加到奖励中，
        # 除非发现的节点被占领，但这已经在上面覆盖了
        reward += newly_discovered_nodes * NODE_DISCOVERED_REWARD
        reward += newly_discovered_credentials * CREDENTIAL_DISCOVERED_REWARD

        reward -= vulnerability.cost

        logger.info("获得奖励: " + vulnerability.reward_string)
        return True, ActionResult(reward=reward, outcome=outcome)

    def exploit_remote_vulnerability(
        self,
        node_id: model.NodeID,
        target_node_id: model.NodeID,
        vulnerability_id: model.VulnerabilityID,
    ) -> ActionResult:
        """
        尝试从源节点对另一个节点进行远程漏洞利用
        使用指定的漏洞。
        """
        if node_id not in self._environment.network.nodes:
            raise ValueError(f"无效的节点ID '{node_id}'")
        if target_node_id not in self._environment.network.nodes:
            raise ValueError(f"无效的目标节点ID '{target_node_id}'")

        source_node_info: model.NodeInfo = self._environment.get_node(node_id)
        target_node_info: model.NodeInfo = self._environment.get_node(target_node_id)

        if not source_node_info.agent_installed:
            if self._throws_on_invalid_actions:
                raise ValueError("代理没有占有源节点 '" + node_id + "'")
            else:
                return ActionResult(reward=Penalty.INVALID_ACTION, outcome=None)

        if target_node_id not in self._discovered_nodes:
            if self._throws_on_invalid_actions:
                raise ValueError("代理尚未发现目标节点 '" + target_node_id + "'")
            else:
                return ActionResult(reward=Penalty.INVALID_ACTION, outcome=None)

        succeeded, result = self.__process_outcome(
            model.VulnerabilityType.REMOTE,
            vulnerability_id,
            target_node_id,
            target_node_info,
            operation_type=OperationType.REMOTE,
            failed_penalty=Penalty.FAILED_REMOTE_EXPLOIT,
            throw_if_vulnerability_not_present=False,
        )

        if succeeded:
            self.__annotate_edge(node_id, target_node_id, EdgeAnnotation.REMOTE_EXPLOIT)

        return result
    def exploit_local_vulnerability(self, node_id: model.NodeID, vulnerability_id: model.VulnerabilityID) -> ActionResult:
        """
        此函数利用节点上的本地漏洞
        它接受目标节点的NodeID和漏洞ID。

        它返回一个漏洞结果对象或None
        """
        graph = self._environment.network
        if node_id not in graph.nodes:
            raise ValueError(f"无效的节点ID '{node_id}'")

        node_info = self._environment.get_node(node_id)

        if not node_info.agent_installed:
            if self._throws_on_invalid_actions:
                raise ValueError(f"代理没有占有节点 '{node_id}'")
            else:
                return ActionResult(reward=Penalty.INVALID_ACTION, outcome=None)

        succeeded, result = self.__process_outcome(
            model.VulnerabilityType.LOCAL,
            vulnerability_id,
            node_id,
            node_info,
            operation_type=OperationType.LOCAL,
            failed_penalty=Penalty.LOCAL_EXPLOIT_FAILED,
            throw_if_vulnerability_not_present=False,
        )

        return result

    def __is_passing_firewall_rules(self, rules: List[model.FirewallRule], port_name: model.PortName) -> bool:
        """判断指定端口的流量是否被指定的防火墙规则允许"""
        for rule in rules:
            if rule.port == port_name:
                if rule.permission == model.RulePermission.ALLOW:
                    return True
                else:
                    logger.debug(f"阻止的流量 - 端口 '{port_name}' 原因: " + rule.reason)
                    return False

        logger.debug(f"阻止的流量 - 端口 '{port_name}' - 原因: 没有为该端口定义规则。")
        return False

    def __is_node_owned_history(self, target_node_id, target_node_data):
        """返回节点上次被占领的时间及其当前是否被占领。"""
        last_previously_owned_at = self._discovered_nodes[target_node_id].last_owned_at if target_node_id in self._discovered_nodes else None

        is_currently_owned = last_previously_owned_at is not None and (target_node_data.last_reimaging is None or last_previously_owned_at >= target_node_data.last_reimaging)
        return last_previously_owned_at, is_currently_owned

    def connect_to_remote_machine(
        self,
        source_node_id: model.NodeID,
        target_node_id: model.NodeID,
        port_name: model.PortName,
        credential: model.CredentialID,
    ) -> ActionResult:
        """
        该函数通过凭证连接到远程机器，而不是通过利用漏洞。
        它接受源节点的NodeID、目标节点的NodeID以及凭证对象。
        """
        graph = self._environment.network
        if source_node_id not in graph.nodes:
            raise ValueError(f"无效的节点ID '{source_node_id}'")
        if target_node_id not in graph.nodes:
            raise ValueError(f"无效的目标节点ID '{target_node_id}'")

        target_node = self._environment.get_node(target_node_id)
        source_node = self._environment.get_node(source_node_id)
        # 确保源节点已被代理拥有
        # 并且目标节点已被发现

        if not source_node.agent_installed:
            if self._throws_on_invalid_actions:
                raise ValueError(f"代理没有占有源节点 '{source_node_id}'")
            else:
                return ActionResult(reward=Penalty.INVALID_ACTION, outcome=None)

        if target_node_id not in self._discovered_nodes:
            if self._throws_on_invalid_actions:
                raise ValueError(f"代理尚未发现目标节点 '{target_node_id}'")
            else:
                return ActionResult(reward=Penalty.INVALID_ACTION, outcome=None)

        if credential not in self._gathered_credentials:
            if self._throws_on_invalid_actions:
                raise ValueError(f"代理尚未发现凭证 '{credential}'")
            else:
                return ActionResult(reward=Penalty.INVALID_ACTION, outcome=None)

        if not self.__is_passing_firewall_rules(source_node.firewall.outgoing, port_name):
            logger.info(f"阻止的流量: 源节点 '{source_node_id}'" + f" 阻止了端口 '{port_name}' 的出站流量")
            return ActionResult(reward=Penalty.BLOCKED_BY_LOCAL_FIREWALL, outcome=None)

        if not self.__is_passing_firewall_rules(target_node.firewall.incoming, port_name):
            logger.info(f"阻止的流量: 目标节点 '{target_node_id}'" + f" 阻止了端口 '{port_name}' 的入站流量")
            return ActionResult(reward=Penalty.BLOCKED_BY_REMOTE_FIREWALL, outcome=None)

        target_node_is_listening = port_name in [i.name for i in target_node.services]
        if not target_node_is_listening:
            logger.info(f"目标节点 '{target_node_id}' 没有监听端口 '{port_name}'")
            return ActionResult(reward=Penalty.SCANNING_UNOPEN_PORT, outcome=None)
        else:
            target_node_data: model.NodeInfo = self._environment.get_node(target_node_id)

            if target_node_data.status != model.MachineStatus.Running:
                logger.info("目标机器未处于运行状态")
                return ActionResult(reward=Penalty.MACHINE_NOT_RUNNING, outcome=None)

            # 在连接之前检查凭证
            if not self._check_service_running_and_authorized(target_node_data, port_name, credential):
                logger.info("提供的凭证无效")
                return ActionResult(reward=Penalty.WRONG_PASSWORD, outcome=None)

            last_owned_at, is_already_owned = self.__mark_node_as_owned(target_node_id)

            if is_already_owned:
                return ActionResult(reward=Penalty.REPEAT, outcome=model.LateralMove())

            if target_node_id not in self._discovered_nodes:
                self._discovered_nodes[target_node_id] = NodeTrackingInformation()

            self.__annotate_edge(source_node_id, target_node_id, EdgeAnnotation.LATERAL_MOVE)

            logger.info(f"通过 '{source_node_id}' 从目标节点 '{target_node_id}'" + f" 使用凭证 '{credential}' 感染节点")
            if target_node.owned_string:
                logger.info("已拥有消息: " + target_node.owned_string)

            return ActionResult(
                reward=float(target_node_data.value) if last_owned_at is None else 0.0,
                outcome=model.LateralMove(),
            )
    def _check_service_running_and_authorized(
        self,
        target_node_data: model.NodeInfo,
        port_name: model.PortName,
        credential: model.CredentialID,
    ) -> bool:
        """
        这是一个快速的辅助函数，用于检查先决条件是否与提供的条件匹配。
        """
        for service in target_node_data.services:
            if service.running and service.name == port_name and credential in service.allowedCredentials:
                return True
        return False

    def list_nodes(self) -> List[DiscoveredNodeInfo]:
        """返回被攻击者发现或拥有的节点ID列表。"""
        return [
            cast(
                DiscoveredNodeInfo,
                {
                    "id": node_id,
                    "status": "owned" if node_info.agent_installed else "discovered",
                },
            )
            for node_id, node_info in self.discovered_nodes()
        ]

    def list_remote_attacks(self, node_id: model.NodeID) -> List[model.VulnerabilityID]:
        """返回可以对指定节点执行的所有远程攻击列表。"""
        attacks: List[model.VulnerabilityID] = self.list_vulnerabilities_in_target(node_id, model.VulnerabilityType.REMOTE)
        return attacks

    def list_local_attacks(self, node_id: model.NodeID) -> List[model.VulnerabilityID]:
        """返回可以对指定节点执行的所有本地攻击列表。"""
        attacks: List[model.VulnerabilityID] = self.list_vulnerabilities_in_target(node_id, model.VulnerabilityType.LOCAL)
        return attacks

    def list_attacks(self, node_id: model.NodeID) -> List[model.VulnerabilityID]:
        """返回可以对指定节点执行的所有攻击列表。"""
        attacks: List[model.VulnerabilityID] = self.list_vulnerabilities_in_target(node_id)
        return attacks

    def list_all_attacks(self) -> List[Dict[str, object]]:
        """列出当前所有攻击者拥有的节点的所有可能攻击。"""
        on_owned_nodes: List[Dict[str, object]] = [
            {
                "id": n["id"],
                "status": n["status"],
                "properties": self._environment.get_node(n["id"]).properties,
                "local_attacks": self.list_local_attacks(n["id"]),
                "remote_attacks": self.list_remote_attacks(n["id"]),
            }
            for n in self.list_nodes()
            if n["status"] == "owned"
        ]
        on_discovered_nodes: List[Dict[str, object]] = [
            {
                "id": n["id"],
                "status": n["status"],
                "local_attacks": None,
                "remote_attacks": self.list_remote_attacks(n["id"]),
            }
            for n in self.list_nodes()
            if n["status"] != "owned"
        ]
        return on_owned_nodes + on_discovered_nodes

    def print_all_attacks(self) -> None:
        """漂亮地打印当前所有攻击者拥有的节点的所有可能攻击。"""
        display(pd.DataFrame.from_dict(self.list_all_attacks()).set_index("id"))  # type: ignore

    def exploit_computation_leak_vulnerability(
        self,
        node_id: model.NodeID,
        vulnerability_id: model.VulnerabilityID,
    ) -> ActionResult:
        """尝试利用节点上的算力泄露漏洞来劫持算力资源"""
        # 验证节点存在
        if node_id not in self._environment.network.nodes:
            raise ValueError(f"无效的节点ID '{node_id}'")
        
        node_info = self._environment.get_node(node_id)
        
        # 验证节点已被攻击者控制
        if not node_info.agent_installed:
            if self._throws_on_invalid_actions:
                raise ValueError(f"代理没有占有节点 '{node_id}'")
            else:
                return ActionResult(reward=Penalty.INVALID_ACTION, outcome=None)
        
        # 处理攻击结果
        succeeded, result = self.__process_outcome(
            model.VulnerabilityType.COMPUTATION_LEAK,
            vulnerability_id,
            node_id,
            node_info,
            operation_type=OperationType.COMPUTATION,  # 使用算力操作类型
            failed_penalty=Penalty.COMPUTATION_EXPLOIT_FAILED,
            throw_if_vulnerability_not_present=False,
        )
        
        # 不需要添加边注释，因为算力劫持是节点本地操作
        if succeeded:
            logger.info(f"成功执行算力劫持攻击: 节点 {node_id}")
        
        return result


class DefenderAgentActions:
    """防御者代理的操作"""

    # 完全重新映像节点所需的步骤数
    REIMAGING_DURATION = 15

    def __init__(self, environment: model.Environment):
        # 将正在重新映像的节点与剩余步骤数映射
        self.node_reimaging_progress: Dict[model.NodeID, int] = dict()

        # 网络的最后可用性计算值
        self.__network_availability: float = 1.0

        self._environment = environment

    @property
    def network_availability(self):
        return self.__network_availability

    def reimage_node(self, node_id: model.NodeID):
        """重新映像计算机节点"""
        # 标记节点为重新映像，并使其在重新映像完成之前不可用
        self.node_reimaging_progress[node_id] = self.REIMAGING_DURATION

        node_info = self._environment.get_node(node_id)
        assert node_info.reimagable, f"节点 {node_id} 无法重新映像"

        node_info.agent_installed = False
        node_info.privilege_level = model.PrivilegeLevel.NoAccess
        node_info.status = model.MachineStatus.Imaging
        node_info.last_reimaging = datetime.datetime.now()
        self._environment.network.nodes[node_id].update({"data": node_info})

    def on_attacker_step_taken(self):
        """每次模拟步骤执行时调用的函数"""
        for node_id in list(self.node_reimaging_progress.keys()):
            remaining_steps = self.node_reimaging_progress[node_id]
            if remaining_steps > 0:
                self.node_reimaging_progress[node_id] -= 1
            else:
                logger.info(f"机器重新映像完成: {node_id}")
                node_data = self._environment.get_node(node_id)
                node_data.status = model.MachineStatus.Running
                self.node_reimaging_progress.pop(node_id)

        # 根据运行的机器和服务计算网络可用性
        total_node_weights = 0
        network_node_availability = 0
        for node_id, node_info in self._environment.nodes():
            total_service_weights = 0
            running_service_weights = 0
            for service in node_info.services:
                total_service_weights += service.sla_weight
                running_service_weights += service.sla_weight * int(service.running)

            if node_info.status == MachineStatus.Running:
                adjusted_node_availability = (1 + running_service_weights) / (1 + total_service_weights)
            else:
                adjusted_node_availability = 0.0

            total_node_weights += node_info.sla_weight
            network_node_availability += adjusted_node_availability * node_info.sla_weight

        self.__network_availability = network_node_availability / total_node_weights
        assert self.__network_availability <= 1.0 and self.__network_availability >= 0.0

    def override_firewall_rule(
        self,
        node_id: model.NodeID,
        port_name: model.PortName,
        incoming: bool,
        permission: model.RulePermission,
    ):
        node_data = self._environment.get_node(node_id)

        def add_or_patch_rule(rules) -> List[FirewallRule]:
            new_rules = []
            has_matching_rule = False
            for r in rules:
                if r.port == port_name:
                    has_matching_rule = True
                    new_rules.append(FirewallRule(r.port, permission))
                else:
                    new_rules.append(r)

            if not has_matching_rule:
                new_rules.append(model.FirewallRule(port_name, permission))
            return new_rules

        if incoming:
            node_data.firewall.incoming = add_or_patch_rule(node_data.firewall.incoming)
        else:
            node_data.firewall.outgoing = add_or_patch_rule(node_data.firewall.outgoing)

    def block_traffic(self, node_id: model.NodeID, port_name: model.PortName, incoming: bool):
        return self.override_firewall_rule(node_id, port_name, incoming, permission=model.RulePermission.BLOCK)

    def allow_traffic(self, node_id: model.NodeID, port_name: model.PortName, incoming: bool):
        return self.override_firewall_rule(node_id, port_name, incoming, permission=model.RulePermission.ALLOW)

    def stop_service(self, node_id: model.NodeID, port_name: model.PortName):
        node_data = self._environment.get_node(node_id)
        assert node_data.status == model.MachineStatus.Running, "机器必须处于运行状态才能停止服务"
        for service in node_data.services:
            if service.name == port_name:
                service.running = False

    def start_service(self, node_id: model.NodeID, port_name: model.PortName):
        node_data = self._environment.get_node(node_id)
        assert node_data.status == model.MachineStatus.Running, "机器必须处于运行状态才能启动服务"
        for service in node_data.services:
            if service.name == port_name:
                service.running = True
