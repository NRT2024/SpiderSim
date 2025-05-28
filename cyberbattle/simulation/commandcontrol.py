# SpiderSim - A Network Attack Simulation Environment
# Copyright (c) 2024 NRT

# This project includes code modified from CyberBattle 
# (https://github.com/microsoft/CyberBattleSim/tree/main/cyberbattle) used under Licensed under the MIT License.


"""一个类似于"指挥与控制"的接口，向人类玩家展示
    攻击者视图和游戏中的动作。
    这包括用于可视化到目前为止已探索的环境部分的命令，
    并且对于每个已安装攻击者客户端的节点，可以在该机器上执行动作。
"""
import networkx as nx
from typing import List, Optional, Dict, Union, Tuple, Set
import plotly.graph_objects as go
import colorsys

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
        """根据节点状态返回颜色"""
        if node_info.agent_installed:
            return '#E91E63'  # 粉红色 - 已拥有节点
        else:
            return '#03A9F4'  # 蓝色 - 已发现但未拥有节点

    def plot_nodes(self) -> None:
        """绘制节点的子图，无论是到目前为止发现的（代理已知其ID）
        还是已拥有的（即安装了攻击者客户端）。
        
        使用纯白色背景和现代可视化样式。
        """
        discovered_nodes = [node_id for node_id, _ in self._actuator.discovered_nodes()]
        
        if not discovered_nodes:
            print("没有发现任何节点可供绘制")
            return
            
        sub_graph = self.__environment.network.subgraph(discovered_nodes)
        
        # 创建更好的布局，添加错误处理
        try:
            # 使用Fruchterman-Reingold布局算法
            pos = nx.fruchterman_reingold_layout(sub_graph, seed=42, k=2.0)
        except Exception as e:
            print(f"布局算法错误: {e}，使用随机布局")
            pos = nx.random_layout(sub_graph, scale=2.0)
        
        # 创建Plotly图表
        fig = go.Figure()
        
        # 设置纯白色背景主题
        fig.update_layout(
            paper_bgcolor='rgba(255, 255, 255, 1)',  # 纯白色背景
            plot_bgcolor='rgba(255, 255, 255, 1)',   # 纯白色背景
        )
        
        # 添加边 - 使用曲线而不是直线
        for edge in sub_graph.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            
            # 计算控制点，使边呈现为曲线
            mid_x = (x0 + x1) / 2
            mid_y = (y0 + y1) / 2
            
            # 添加一个小的偏移以创建曲线效果
            offset = 0.05
            ctrl_x = mid_x + offset * (-(y1 - y0))
            ctrl_y = mid_y + offset * (x1 - x0)
            
            # 创建曲线路径
            curve_x = [x0, ctrl_x, x1]
            curve_y = [y0, ctrl_y, y1]
            
            # 添加边的曲线
            fig.add_trace(go.Scatter(
                x=curve_x,
                y=curve_y,
                mode='lines',
                line=dict(
                    width=1.5,
                    color='rgba(100, 100, 100, 0.5)',  # 半透明灰色
                    shape='spline'  # 使用样条曲线
                ),
                hoverinfo='none',
                showlegend=False
            ))
            
            # 添加箭头指示方向
            fig.add_annotation(
                x=x1,
                y=y1,
                ax=curve_x[1],
                ay=curve_y[1],
                xref="x",
                yref="y",
                axref="x",
                ayref="y",
                showarrow=True,
                arrowhead=2,
                arrowsize=1.5,
                arrowwidth=1.5,
                arrowcolor='rgba(100, 100, 100, 0.7)',
                standoff=5
            )
        
        # 节点状态和颜色
        node_owned = [node for node in sub_graph.nodes() if self.__environment.get_node(node).agent_installed]
        node_discovered = [node for node in sub_graph.nodes() if not self.__environment.get_node(node).agent_installed]
        
        # 添加已拥有的节点
        if node_owned:
            fig.add_trace(go.Scatter(
                x=[pos[node][0] for node in node_owned],
                y=[pos[node][1] for node in node_owned],
                mode='markers+text',
                name='已拥有节点',
                marker=dict(
                    symbol='hexagon',  # 六边形标记
                    size=25,
                    color='#C2185B',  # 深粉红色
                    line=dict(width=2, color='#880E4F'),  # 更深的粉红色边框
                    opacity=0.9
                ),
                text=[node for node in node_owned],
                hovertext=[f"节点: {node}<br>状态: 已拥有" for node in node_owned],
                hoverinfo='text',
                textposition="bottom center",
                textfont=dict(size=12, color="#212121")
            ))
        
        # 添加已发现但未拥有的节点
        if node_discovered:
            fig.add_trace(go.Scatter(
                x=[pos[node][0] for node in node_discovered],
                y=[pos[node][1] for node in node_discovered],
                mode='markers+text',
                name='已发现节点',
                marker=dict(
                    symbol='circle',  # 圆形标记
                    size=20,
                    color='#0277BD',  # 深蓝色
                    line=dict(width=2, color='#01579B'),  # 更深的蓝色边框
                    opacity=0.9
                ),
                text=[node for node in node_discovered],
                hovertext=[f"节点: {node}<br>状态: 已发现" for node in node_discovered],
                hoverinfo='text',
                textposition="bottom center",
                textfont=dict(size=12, color="#212121")
            ))
        
        # 更新布局
        fig.update_layout(
            title=dict(
                text="网络攻击拓扑图",
                font=dict(size=24, color="#212121"),
                x=0.5,
                y=0.95
            ),
            showlegend=True,
            hovermode='closest',
            width=1200,  # 增加图表宽度
            height=800,  # 增加图表高度
            margin=dict(b=20, l=20, r=20, t=60),
            xaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                showline=False,
                range=[-1.2, 1.2]  # 扩大坐标范围以避免节点靠近边缘
            ),
            yaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                showline=False,
                range=[-1.2, 1.2]
            ),
            legend=dict(
                x=0.01,
                y=0.99,
                bgcolor='rgba(240, 240, 240, 0.8)',  # 半透明浅灰色背景
                bordercolor="#757575",
                borderwidth=1,
                font=dict(color="#212121"),
                orientation="v",
                xanchor="left",
                yanchor="top"
            )
        )
        
        fig.show(config={'displayModeBar': True, 'scrollZoom': True})

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
        """生成用于绘制网络的Plotly跟踪和布局
        
        Args:
            xref: x轴引用
            yref: y轴引用
            
        Returns:
            Tuple[List[go.Scatter], dict]: 包含散点图和布局的元组
        """
        known_nodes = [node_id for node_id, _ in self.__actuator.discovered_nodes()]
        
        if not known_nodes:
            return [], {}
            
        # 获取环境的完整网络，但只保留已知节点
        subgraph = self.__environment.network.subgraph(known_nodes)
        
        # 使用更好的布局算法，并添加错误处理
        try:
            # 尝试使用Fruchterman-Reingold布局算法
            pos = nx.fruchterman_reingold_layout(subgraph, k=2.0, seed=42)
        except Exception as e:
            print(f"布局算法错误: {e}，使用随机布局")
            pos = nx.random_layout(subgraph, scale=2.0)
        
        # 定义边的文本和颜色函数
        def edge_text(source: model.NodeID, target: model.NodeID) -> str:
            """获取边的悬停文本"""
            data = self.__environment.network.get_edge_data(source, target)
            if 'kind' in data:
                name: str = data['kind'].name
                return f"攻击类型: {name}"
            return "未知连接"
        
        # 定义适合白色背景的颜色映射
        color_map = {
            actions.EdgeAnnotation.LATERAL_MOVE: '#D81B60',       # 深粉色
            actions.EdgeAnnotation.REMOTE_EXPLOIT: '#E65100',     # 深橙色
            actions.EdgeAnnotation.KNOWS: '#455A64',              # 深灰蓝色
            actions.EdgeAnnotation.LOCAL_EXPLOIT: '#0288D1',      # 深蓝色
            actions.EdgeAnnotation.CONNECT: '#00796B',            # 深绿色
            actions.EdgeAnnotation.COMPUTATION_EXPLOIT: '#7B1FA2'  # 深紫色
        }
        
        def edge_color(source: model.NodeID, target: model.NodeID) -> str:
            """获取边的颜色"""
            data = self.__environment.network.get_edge_data(source, target)
            if 'kind' in data:
                return color_map[data['kind']]
            return '#757575'  # 灰色作为默认值
        
        # 创建纯白色背景布局
        layout: dict = dict(
            paper_bgcolor='rgba(255, 255, 255, 1)',  # 纯白色背景
            plot_bgcolor='rgba(255, 255, 255, 1)',   # 纯白色背景
            title=dict(
                text="SpiderSim 网络攻击图",
                font=dict(size=24, color="#212121", family="Arial"),
                x=0.5,
                xanchor="center"
            ),
            font=dict(size=14, family="Arial", color="#212121"),
            showlegend=True,
            autosize=True,
            width=1200,
            height=800,
            margin=go.layout.Margin(l=20, r=20, b=20, t=60),
            hovermode='closest',
            legend=dict(
                x=0.01,
                y=0.99,
                bgcolor='rgba(255, 255, 255, 0.8)',  # 半透明白色背景
                bordercolor="#757575",
                borderwidth=1,
                orientation="v",
                xanchor="left",
                yanchor="top"
            ),
            xaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                showline=False,
                range=[-1.2, 1.2]  # 扩大坐标范围以避免节点靠近边缘
            ),
            yaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                showline=False,
                range=[-1.2, 1.2]
            ),
        )
        
        # 创建注释列表
        annotations = []
        
        # 跟踪已处理的边，避免重复
        processed_edges = set()
        
        # 为每条边创建曲线和箭头
        edge_traces = []
        
        # 首先获取所有边的详细信息，包括类型
        all_edges = []
        for source, target in list(subgraph.edges()):
            data = self.__environment.network.get_edge_data(source, target)
            kind = data.get('kind', None)
            if kind is not None:
                all_edges.append((source, target, kind))
        
        # 确保KNOWS类型的边优先被绘制在下层，其他类型的边绘制在上层
        all_edges.sort(key=lambda x: 0 if x[2] == actions.EdgeAnnotation.KNOWS else 1)
        
        for source, target, kind in all_edges:
            # 跳过已处理的边
            edge_key = (source, target)
            if edge_key in processed_edges:
                continue
                
            processed_edges.add(edge_key)
            
            # 如果位置信息不存在，跳过
            if source not in pos or target not in pos:
                continue
                
            x0, y0 = pos[source]
            x1, y1 = pos[target]
            
            # 计算控制点，使边呈现为曲线
            mid_x = (x0 + x1) / 2
            mid_y = (y0 + y1) / 2
            
            # 添加一个小的偏移以创建曲线效果
            # 根据节点间距动态调整偏移量，避免曲线过度弯曲
            distance = ((x1 - x0)**2 + (y1 - y0)**2)**0.5
            offset = min(0.05, distance * 0.1)  # 限制最大偏移量
            
            ctrl_x = mid_x + offset * (-(y1 - y0))
            ctrl_y = mid_y + offset * (x1 - x0)
            
            # KNOWS类型的边使用较小的偏移
            if kind == actions.EdgeAnnotation.KNOWS:
                offset = min(0.02, distance * 0.05)
                ctrl_x = mid_x + offset * (-(y1 - y0))
                ctrl_y = mid_y + offset * (x1 - x0)
            
            # 创建平滑的曲线路径，使用更多点来避免分叉
            t_values = [0, 0.2, 0.4, 0.6, 0.8, 1.0]  # 增加点的数量
            curve_x = []
            curve_y = []
            
            for t in t_values:
                # 二次贝塞尔曲线
                bx = (1-t)**2 * x0 + 2*(1-t)*t * ctrl_x + t**2 * x1
                by = (1-t)**2 * y0 + 2*(1-t)*t * ctrl_y + t**2 * y1
                curve_x.append(bx)
                curve_y.append(by)
            
            # 获取边的颜色
            edge_clr = color_map[kind]
            
            # 根据边的类型调整线宽和透明度
            line_width = 3
            opacity = 0.8
            
            if kind == actions.EdgeAnnotation.KNOWS:
                line_width = 1.5
                opacity = 0.5
            
            # 添加边的曲线
            edge_trace = go.Scatter(
                x=curve_x,
                y=curve_y,
                mode='lines',
                line=dict(
                    width=line_width,
                    color=edge_clr,
                    shape='spline'  # 使用样条曲线
                ),
                hovertext=f"攻击类型: {kind.name}",
                hoverinfo='text',
                showlegend=False,
                opacity=opacity
            )
            edge_traces.append(edge_trace)
            
            # 对非KNOWS类型的边添加箭头
            if kind != actions.EdgeAnnotation.KNOWS:
                # 添加箭头注释，位置调整为曲线的80%处，避免与节点重叠
                arrow_x = curve_x[-2]  # 使用倒数第二个点
                arrow_y = curve_y[-2]
                
                # 计算箭头方向，使用曲线上的相邻点来确定
                dx = curve_x[-1] - curve_x[-2]
                dy = curve_y[-1] - curve_y[-2]
                
                # 添加箭头注释
                annotation = dict(
                    x=arrow_x + dx * 0.5,  # 将箭头放在曲线的90%处
                    y=arrow_y + dy * 0.5,
                    ax=arrow_x - dx * 0.1,  # 箭头起点稍微后移
                    ay=arrow_y - dy * 0.1,
                    xref=xref,
                    yref=yref,
                    axref=xref,
                    ayref=yref,
                    showarrow=True,
                    arrowhead=2,
                    arrowsize=1.5,
                    arrowwidth=2,
                    arrowcolor=edge_clr,
                    standoff=5,
                    opacity=0.9
                )
                annotations.append(annotation)
        
        # 添加注释到布局
        layout['annotations'] = annotations
        
        # 分离已拥有和已发现的节点
        owned_nodes_coordinates = [(i, c) for i, c in pos.items()
                                   if self.get_node_information(i).agent_installed]
        discovered_nodes_coordinates = [(i, c)
                                        for i, c in pos.items()
                                        if not self.get_node_information(i).agent_installed]
        
        # 创建改进的已拥有节点散点图 - 使用六边形
        trace_owned_nodes = go.Scatter(
            x=[c[0] for i, c in owned_nodes_coordinates],
            y=[c[1] for i, c in owned_nodes_coordinates],
            mode='markers+text',
            name='已拥有节点',
            marker=dict(
                symbol='hexagon',  # 六边形标记
                size=25,
                color='#C2185B',  # 深粉红色
                line=dict(color='#880E4F', width=2),  # 更深的粉红色边框
                opacity=0.9
            ),
            text=[i for i, c in owned_nodes_coordinates],
            hovertext=[f"节点: {i}<br>状态: 已拥有" for i, _ in owned_nodes_coordinates],
            hoverinfo='text',
            textposition="bottom center",
            textfont=dict(size=14, color="#212121")
        )
        
        # 创建改进的已发现节点散点图 - 使用圆形
        trace_discovered_nodes = go.Scatter(
            x=[c[0] for i, c in discovered_nodes_coordinates],
            y=[c[1] for i, c in discovered_nodes_coordinates],
            mode='markers+text',
            name='已发现节点',
            marker=dict(
                symbol='circle',  # 圆形标记
                size=20,
                color='#0277BD',  # 深蓝色
                line=dict(color='#01579B', width=2),  # 更深的蓝色边框
                opacity=0.9
            ),
            text=[i for i, c in discovered_nodes_coordinates],
            hovertext=[f"节点: {i}<br>状态: 已发现" for i, _ in discovered_nodes_coordinates],
            hoverinfo='text',
            textposition="bottom center",
            textfont=dict(size=14, color="#212121")
        )
        
        # 为边类型创建图例
        dummy_scatter_for_edge_legend = [
            go.Scatter(
                x=[None], y=[None], mode="lines",
                line=dict(color=color_map[a], width=4),
                name=a.name,
                legendgroup=a.name
            ) for a in actions.EdgeAnnotation
        ]
        
        # 组合所有跟踪
        all_scatters = [trace_owned_nodes, trace_discovered_nodes] + edge_traces + dummy_scatter_for_edge_legend
        return (all_scatters, layout)

    def plot_discovered_network(self) -> None:
        """使用 plotly 绘制网络图
        
        展示已发现和已拥有的节点，以及它们之间的连接。
        使用纯白色背景和现代视觉效果。
        """
        fig = go.Figure()
        traces, layout = self.network_as_plotly_traces()
        
        if not traces:
            print("没有发现任何节点可供绘制")
            return
            
        for t in traces:
            fig.add_trace(t)
            
        fig.update_layout(layout)
        
        # 添加额外的交互性
        fig.update_layout(
            updatemenus=[
                dict(
                    type="buttons",
                    direction="left",
                    buttons=[
                        dict(
                            args=[{"visible": [True] * len(traces)}],
                            label="显示全部",
                            method="update"
                        ),
                        dict(
                            args=[{"visible": [True, True] + [True] * (len(traces) - 8) + [False] * 6}],
                            label="隐藏图例",
                            method="update"
                        )
                    ],
                    pad={"r": 10, "t": 10},
                    showactive=True,
                    x=0.1,
                    xanchor="left",
                    y=1.1,
                    yanchor="top",
                    bgcolor='rgba(240, 240, 240, 0.8)',
                    font=dict(color="#212121")
                ),
            ]
        )
        
        # 启用滚动缩放和其他交互功能
        fig.show(config={
            'displayModeBar': True,
            'scrollZoom': True,
            'modeBarButtonsToAdd': ['drawclosedpath', 'eraseshape']
        })

    def get_node_information(self, node_id: model.NodeID) -> model.NodeInfo:
        """打印节点信息"""
        return self.__environment.get_node(node_id)
