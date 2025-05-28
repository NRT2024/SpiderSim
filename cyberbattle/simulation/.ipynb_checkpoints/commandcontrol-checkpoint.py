# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""一个类似于“指挥与控制”的接口，向人类玩家展示
    攻击者视图和游戏中的动作。
    这包括用于可视化到目前为止已探索的环境部分的命令，
    并且对于每个已安装攻击者客户端的节点，可以在该机器上执行动作。
"""
import networkx as nx
from typing import List, Optional, Dict, Union, Tuple, Set
import plotly.graph_objects as go

from . import model, actions


class CommandControl:
    """仿真中的指挥与控制接口。

    这是一个集中从网络节点上运行的各个客户端收集信息和机密的服务器。
    """

    # 全局列表，汇总到目前为止从网络中的任何节点收集的所有凭证
    __gathered_credentials: Set[model.CachedCredential]
    _actuator: actions.AgentActions
    __environment: model.Environment
    __total_reward: float

    def __init__(self, environment_or_actuator: Union[model.Environment, actions.AgentActions]):
        if isinstance(environment_or_actuator, model.Environment):
            self.__environment = environment_or_actuator
            self._actuator = actions.AgentActions(self.__environment, throws_on_invalid_actions=True)
        elif isinstance(environment_or_actuator, actions.AgentActions):
            self.__environment = environment_or_actuator._environment
            self._actuator = environment_or_actuator
        else:
            raise ValueError(
                "无效类型：期望 Union[model.Environment, actions.AgentActions])")

        self.__gathered_credentials = set()
        self.__total_reward = 0

    def __save_credentials(self, outcome: model.VulnerabilityOutcome) -> None:
        """保存通过利用漏洞获得的凭证"""
        if isinstance(outcome, model.LeakedCredentials):
            self.__gathered_credentials.update(outcome.credentials)
        return

    def __accumulate_reward(self, reward: actions.Reward) -> None:
        """累计新的奖励"""
        self.__total_reward += reward

    def total_reward(self) -> actions.Reward:
        """返回当前累计的奖励"""
        return self.__total_reward

    def list_nodes(self) -> List[actions.DiscoveredNodeInfo]:
        """返回攻击者已发现或拥有的节点ID列表。"""
        return self._actuator.list_nodes()

    def get_node_color(self, node_info: model.NodeInfo) -> str:
        if node_info.agent_installed:
            return 'red'
        else:
            return 'green'

    def plot_nodes(self) -> None:
        """绘制节点的子图，无论是到目前为止发现的（代理已知其ID）
        还是已拥有的（即安装了攻击者客户端）。"""
        discovered_nodes = [node_id for node_id, _ in self._actuator.discovered_nodes()]
        sub_graph = self.__environment.network.subgraph(discovered_nodes)
        nx.draw(sub_graph,
                with_labels=True,
                node_color=[self.get_node_color(self.__environment.get_node(i)) for i in sub_graph.nodes])

    def known_vulnerabilities(self) -> model.VulnerabilityLibrary:
        """返回已知漏洞的全局列表。"""
        return self.__environment.vulnerability_library

    def list_remote_attacks(self, node_id: model.NodeID) -> List[model.VulnerabilityID]:
        """返回Command&Control可以对指定节点执行的所有远程攻击列表。"""
        return self._actuator.list_remote_attacks(node_id)

    def list_local_attacks(self, node_id: model.NodeID) -> List[model.VulnerabilityID]:
        """返回Command&Control可以对指定节点执行的所有本地攻击列表。"""
        return self._actuator.list_local_attacks(node_id)

    def list_attacks(self, node_id: model.NodeID) -> List[model.VulnerabilityID]:
        """返回Command&Control可以对指定节点执行的所有攻击列表。"""
        return self._actuator.list_attacks(node_id)

    def list_all_attacks(self) -> List[Dict[str, object]]:
        """列出当前攻击者已拥有的所有节点的所有可能攻击。"""
        return self._actuator.list_all_attacks()

    def print_all_attacks(self) -> None:
        """打印当前攻击者已拥有的所有节点的所有可能攻击列表。"""
        return self._actuator.print_all_attacks()

    def run_attack(self,
                   node_id: model.NodeID,
                   vulnerability_id: model.VulnerabilityID
                   ) -> Optional[model.VulnerabilityOutcome]:
        """运行攻击并尝试利用指定节点的漏洞。"""
        result = self._actuator.exploit_local_vulnerability(node_id, vulnerability_id)
        if result.outcome is not None:
            self.__save_credentials(result.outcome)
        self.__accumulate_reward(result.reward)
        return result.outcome

    def run_remote_attack(self, node_id: model.NodeID,
                          target_node_id: model.NodeID,
                          vulnerability_id: model.VulnerabilityID
                          ) -> Optional[model.VulnerabilityOutcome]:
        """运行从指定节点到目标节点的远程攻击，利用目标节点的远程漏洞"""

        result = self._actuator.exploit_remote_vulnerability(
            node_id, target_node_id, vulnerability_id)
        if result.outcome is not None:
            self.__save_credentials(result.outcome)
        self.__accumulate_reward(result.reward)
        return result.outcome

    def connect_and_infect(self, source_node_id: model.NodeID,
                           target_node_id: model.NodeID,
                           port_name: model.PortName,
                           credentials: model.CredentialID) -> bool:
        """使用提供的凭证在远程机器上安装代理"""
        result = self._actuator.connect_to_remote_machine(source_node_id, target_node_id, port_name,
                                                          credentials)
        self.__accumulate_reward(result.reward)
        return result.outcome is not None

    @property
    def credentials_gathered_so_far(self) -> Set[model.CachedCredential]:
        """返回迄今为止由攻击者收集的凭证列表（来自任何节点）"""
        return self.__gathered_credentials


def get_outcome_first_credential(outcome: Optional[model.VulnerabilityOutcome]) -> model.CredentialID:
    """返回在给定漏洞利用结果中的第一个凭证"""
    if outcome is not None and isinstance(outcome, model.LeakedCredentials):
        return outcome.credentials[0].credential
    else:
        raise ValueError('漏洞结果中不包含任何凭证')


class EnvironmentDebugging:
    """提供调试功能，暴露环境的内部内容
     这些内容通常不会根据仿真规则暴露给攻击者代理。
    """
    __environment: model.Environment
    __actuator: actions.AgentActions

    def __init__(self, actuator_or_c2: Union[actions.AgentActions, CommandControl]):
        if isinstance(actuator_or_c2, actions.AgentActions):
            self.__actuator = actuator_or_c2
        elif isinstance(actuator_or_c2, CommandControl):
            self.__actuator = actuator_or_c2._actuator
        else:
            raise ValueError("无效类型：期望 Union[actions.AgentActions, CommandControl])")

        self.__environment = self.__actuator._environment

    def network_as_plotly_traces(self, xref: str = "x", yref: str = "y") -> Tuple[List[go.Scatter], dict]:
        known_nodes = [node_id for node_id, _ in self.__actuator.discovered_nodes()]

        subgraph = self.__environment.network.subgraph(known_nodes)

        # pos = nx.fruchterman_reingold_layout(subgraph)
        pos = nx.shell_layout(subgraph, [[known_nodes[0]], known_nodes[1:]])

        def edge_text(source: model.NodeID, target: model.NodeID) -> str:
            data = self.__environment.network.get_edge_data(source, target)
            name: str = data['kind'].name
            return name

        color_map = {actions.EdgeAnnotation.LATERAL_MOVE: 'red',
                     actions.EdgeAnnotation.REMOTE_EXPLOIT: 'orange',
                     actions.EdgeAnnotation.KNOWS: 'gray'}

        def edge_color(source: model.NodeID, target: model.NodeID) -> str:
            data = self.__environment.network.get_edge_data(source, target)
            if 'kind' in data:
                return color_map[data['kind']]
            return 'black'

        layout: dict = dict(title="CyberBattle 仿真", font=dict(size=10), showlegend=True,
                            autosize=False, width=800, height=400,
                            margin=go.layout.Margin(l=2, r=2, b=15, t=35),
                            hovermode='closest',
                            annotations=[dict(
                                ax=pos[source][0],
                                ay=pos[source][1], axref=xref, ayref=yref,
                                x=pos[target][0],
                                y=pos[target][1], xref=xref, yref=yref,
                                arrowcolor=edge_color(source, target),
                                hovertext=edge_text(source, target),
                                showarrow=True,
                                arrowhead=1,
                                arrowsize=1,
                                arrowwidth=1,
                                startstandoff=10,
                                standoff=10,
                                align='center',
                                opacity=1
                            ) for (source, target) in list(subgraph.edges)]
                            )

        owned_nodes_coordinates = [(i, c) for i, c in pos.items()
                                   if self.get_node_information(i).agent_installed]
        discovered_nodes_coordinates = [(i, c)
                                        for i, c in pos.items()
                                        if not self.get_node_information(i).agent_installed]

        trace_owned_nodes = go.Scatter(
            x=[c[0] for i, c in owned_nodes_coordinates],
            y=[c[1] for i, c in owned_nodes_coordinates],
            mode='markers+text',
            name='owned',
            marker=dict(symbol='circle-dot',
                        size=5,
                        # green #0e9d00
                        color='#D32F2E',  # red
                        line=dict(color='rgb(255,0,0)', width=8)
                        ),
            text=[i for i, c in owned_nodes_coordinates],
            hoverinfo='text',
            textposition="bottom center"
        )

        trace_discovered_nodes = go.Scatter(
            x=[c[0] for i, c in discovered_nodes_coordinates],
            y=[c[1] for i, c in discovered_nodes_coordinates],
            mode='markers+text',
            name='discovered',
            marker=dict(symbol='circle-dot',
                        size=5,
                        color='#0e9d00',  # green
                        line=dict(color='rgb(0,255,0)', width=8)
                        ),
            text=[i for i, c in discovered_nodes_coordinates],
            hoverinfo='text',
            textposition="bottom center"
        )

        dummy_scatter_for_edge_legend = [
            go.Scatter(
                x=[0], y=[0], mode="lines",
                line=dict(color=color_map[a]),
                name=a.name
            ) for a in actions.EdgeAnnotation]

        all_scatters = dummy_scatter_for_edge_legend + [trace_owned_nodes, trace_discovered_nodes]
        return (all_scatters, layout)

    def plot_discovered_network(self) -> None:
        """使用 plotly 绘制网络图"""
        fig = go.Figure()
        traces, layout = self.network_as_plotly_traces()
        for t in traces:
            fig.add_trace(t)
        fig.update_layout(layout)
        fig.show()

    def get_node_information(self, node_id: model.NodeID) -> model.NodeInfo:
        """打印节点信息"""
        return self.__environment.get_node(node_id)
