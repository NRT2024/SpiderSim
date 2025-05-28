# SpiderSim - A Network Attack Simulation Environment
# Copyright (c) 2024 NRT

# This project includes code modified from CyberBattle 
# (https://github.com/microsoft/CyberBattleSim/tree/main/cyberbattle) used under Licensed under the MIT License.


from typing import Union, Tuple

import gym
import numpy as onp
import networkx as nx

from .graph_spaces import DiGraph


Action = Union[Tuple[int, int], Tuple[int, int, int], Tuple[int, int, int, int]]


class CyberBattleGraph(gym.Wrapper):
    """ 

    一个CyberBattleSim的包装器，用于维护代理的
    知识图，包含关于已探索网络子集的信息。

    目前，该图的节点是环境节点的子集。
    最终，我们将添加新节点类型来表示各种实体
    如凭证和用户。边将表示这些实体之间的关系
    （例如，用户X使用凭证Z通过机器Y进行身份验证）。

    动作
    ----

    动作的形式为：

    .. code:: python

        (kind, *indicators)


    ``kind`` 可能的值之一：

    .. code:: python

        # kind
        0: 本地漏洞
        1: 远程漏洞
        2: 连接

    指示符根据 ``kind`` 变化，具有不同的含义和长度：

    .. code:: python

        # kind=0 (本地漏洞)
        indicators = (node_id, local_vulnerability_id)

        # kind=1 (远程漏洞)
        indicators = (from_node_id, to_node_id, remote_vulnerability_id)

        # kind=2 (连接)
        indicators = (from_node_id, to_node_id, port_id, credential_id)

    节点ID可以从图中获得，例如：

    .. code:: python

        node_ids = observation['graph'].keys()

    其他指示符如下所示：

    .. code:: python

        # local_vulnerability_ids
        0: ScanBashHistory
        1: ScanExplorerRecentFiles
        2: SudoAttempt
        3: CrackKeepPassX
        4: CrackKeepPass

        # remote_vulnerability_ids
        0: ProbeLinux
        1: ProbeWindows

        # port_ids
        0: HTTPS
        1: GIT
        2: SSH
        3: RDP
        4: PING
        5: MySQL
        6: SSH-key
        7: su

    示例
    ~~~~~~~~
    以下是一些示例动作：

    .. code:: python

        a = (0, 5, 3)        # 尝试在节点5上使用本地漏洞 "CrackKeepPassX"
        a = (1, 5, 7, 1)     # 尝试从节点5到节点7使用远程漏洞 "ProbeWindows"
        a = (2, 5, 7, 3, 2)  # 尝试使用凭证2通过RDP端口从节点5连接到节点7


    观察
    ----

    观察是已发现节点的图形。每个节点都有一个字典，包含以下形式的属性：

    .. code:: python

        node_properties = {
            'name': 'FooServer',                         # 可读的名称
            'privilege_level': 1,                        # 0: 未拥有, 1: 管理员, 2: 系统
            'flags': array(-1, 0,  1, 0,  0, ...,  0]),  # 1: 设置, -1: 未设置, 0: 未知
            'credentials': array([-1, 5, -1, ..., -1]),  # 端口数组 (-1表示没有凭证)
            'has_leaked_creds': True,                    # 是否有凭证泄露
        }

        # flag_ids
        0: Windows
        1: Linux
        2: ApacheWebSite
        3: IIS_2019
        4: IIS_2020_patched
        5: MySql
        6: Ubuntu
        7: nginx/1.10.3
        8: SMB_vuln
        9: SMB_vuln_patched
        10: SQLServer
        11: Win10
        12: Win10Patched
        13: FLAG:Linux

    请注意，``'credentials'`` 中非平凡端口号的位置对应于凭证ID。因此，对于上面的节点示例，
    我们在 :code:`port_id=5` 上有一个已知凭证，凭证ID为 :code:`credential_id=1`（在数组中的位置）。


    """
    __kinds = ('local_vulnerability', 'remote_vulnerability', 'connect')

    def __init__(self, env, maximum_total_credentials=22, maximum_node_count=22):
        super().__init__(env)
        self._bounds = self.env.bounds
        self.__graph = nx.DiGraph()
        self.observation_space = DiGraph(self.bounds.maximum_node_count)

    def reset(self):
        observation = self.env.reset()
        self.__graph = nx.DiGraph()
        self.__add_node(observation)
        self.__update_nodes(observation)
        return self.__graph

    def step(self, action: Action):
        """ 

        在MDP中采取一步操作。

        参数:
            action: 一个 *抽象* 动作。

        返回:
            observation: 下一步的观察。
            reward: 与给定动作（和前一步观察）相关的奖励。
            done: 下一步的观察是否为终止状态。
            info: 一些附加信息。

        """
        kind_id, *indicators = action
        observation, reward, done, info = self.env.step({self.__kinds[kind_id]: indicators})
        for _ in range(observation['newly_discovered_nodes_count']):
            self.__add_node(observation)
        if True:  # TODO: 我们是否需要每次都更新边和节点？
            self.__update_edges(observation)
            self.__update_nodes(observation)
        return self.__graph, reward, done, info

    def __add_node(self, observation):
        while self.__graph.number_of_nodes() < observation['discovered_node_count']:
            node_index = self.__graph.number_of_nodes()
            creds = onp.full(self._bounds.maximum_total_credentials, -1, dtype=onp.int8)
            self.__graph.add_node(
                node_index,
                name=observation['_discovered_nodes'][node_index],
                privilege_level=None, flags=None,  # 这些由 __update_nodes() 设置
                credentials=creds,
                has_leaked_creds=False,
            )

    def __update_edges(self, observation):
        g_orig = observation['_explored_network']
        node_ids = {n: i for i, n in enumerate(observation['_discovered_nodes'])}
        for (from_name, to_name), edge_properties in g_orig.edges.items():
            self.__graph.add_edge(node_ids[from_name], node_ids[to_name], **edge_properties)

    def __update_nodes(self, observation):
        node_properties = zip(
            observation['nodes_privilegelevel'],
            observation['discovered_nodes_properties'],
        )
        for node_id, (privilege_level, flags) in enumerate(node_properties):
            # 这个值已经在 self.__graph.nodes[node_id]['data'].privilege_level 中提供
            self.__graph.nodes[node_id]['privilege_level'] = privilege_level
            # 这个值已经在 self.__graph.nodes[node_id]['data'].properties 中提供
            self.__graph.nodes[node_id]['flags'] = flags

        for cred_id, (node_id, port_id) in enumerate(observation['credential_cache_matrix']):
            node_id, port_id = int(node_id), int(port_id)
            # 注意：此代码忽略了同一凭证ID用于两个不同端口的情况
            self.__graph.nodes[node_id]['credentials'][cred_id] = port_id
            # 标记节点为泄漏凭证
            self.__graph.nodes[node_id]['has_leaked_creds'] = True
