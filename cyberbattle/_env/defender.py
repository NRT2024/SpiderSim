# SpiderSim - A Network Attack Simulation Environment
# Copyright (c) 2024 NRT

# This project includes code modified from CyberBattle 
# (https://github.com/microsoft/CyberBattleSim/tree/main/cyberbattle) used under Licensed under the MIT License.


"""
定义默认防御者代理。
"""
import random
import numpy
from abc import abstractmethod
from cyberbattle.simulation.model import Environment
from cyberbattle.simulation.actions import DefenderAgentActions
from ..simulation import model

import logging


class DefenderAgent:
    """定义防御者代理的步骤函数。
    在攻击者代理执行每一步之后被调用。"""

    @abstractmethod
    def step(self, environment: Environment, actions: DefenderAgentActions, t: int):
        return None


class ScanAndReimageCompromisedMachines(DefenderAgent):
    """一个防御者代理，它扫描网络节点的一部分
     以固定概率检测到给定节点上的攻击者，并在检测到时重新安装受感染的节点。

    probability -- 在扫描时，攻击者代理存在时被检测到的概率
    scan_capacity -- 防御者代理在一个仿真步骤中能够扫描的最大机器数量
    scan_frequency -- 扫描频率，以仿真步骤为单位
    """

    def __init__(self, probability: float, scan_capacity: int, scan_frequency: int):
        self.probability = probability
        self.scan_capacity = scan_capacity
        self.scan_frequency = scan_frequency

    def step(self, environment: Environment, actions: DefenderAgentActions, t: int):
        if t % self.scan_frequency == 0:
            # 随机扫描节点
            scanned_nodes = random.choices(list(environment.network.nodes), k=self.scan_capacity)
            for node_id in scanned_nodes:
                node_info = environment.get_node(node_id)
                if node_info.status == model.MachineStatus.Running and \
                        node_info.agent_installed:
                    is_malware_detected = numpy.random.random() <= self.probability
                    if is_malware_detected:
                        if node_info.reimagable:
                            logging.info(f"防御者检测到恶意软件，正在重新安装节点 {node_id}")
                            actions.reimage_node(node_id)
                        else:
                            logging.info(f"防御者检测到恶意软件，但节点无法重新安装 {node_id}")


class ExternalRandomEvents(DefenderAgent):
    """一个“防御者”，它随机更改网络节点配置"""

    def step(self, environment: Environment, actions: DefenderAgentActions, t: int):
        self.patch_vulnerabilities_at_random(environment)
        self.stop_service_at_random(environment, actions)
        self.plant_vulnerabilities_at_random(environment)
        self.firewall_change_remove(environment)
        self.firewall_change_add(environment)

    def patch_vulnerabilities_at_random(self, environment: Environment, probability: float = 0.1) -> None:
        # 遍历每个节点。
        for node_id, node_data in environment.nodes():
            # 使用一个布尔值 remove_vulnerability 来决定是否移除一个漏洞。
            remove_vulnerability = numpy.random.random() <= probability
            if remove_vulnerability and len(node_data.vulnerabilities) > 0:
                choice = random.choice(list(node_data.vulnerabilities))
                node_data.vulnerabilities.pop(choice)

    def stop_service_at_random(self, environment: Environment, actions: DefenderAgentActions, probability: float = 0.1) -> None:
        for node_id, node_data in environment.nodes():
            remove_service = numpy.random.random() <= probability
            if remove_service and len(node_data.services) > 0:
                service = random.choice(node_data.services)
                actions.stop_service(node_id, service.name)

    def plant_vulnerabilities_at_random(self, environment: Environment, probability: float = 0.1) -> None:
        for node_id, node_data in environment.nodes():
            add_vulnerability = numpy.random.random() <= probability
            # 查看当前节点漏洞与全局漏洞的差异。
            new_vulnerabilities = numpy.setdiff1d(
                list(environment.vulnerability_library.keys()), list(node_data.vulnerabilities.keys()))
            # 如果我们决定添加漏洞并且有新的漏洞尚未在节点上，则添加它们。
            if add_vulnerability and len(new_vulnerabilities) > 0:
                new_vulnerability = random.choice(new_vulnerabilities)
                node_data.vulnerabilities[new_vulnerability] = \
                    environment.vulnerability_library[new_vulnerability]

    """
    TODO: 不确定如何访问全局（环境）服务。
    def serviceChangeAdd(self, probability: float) -> None:
        # 遍历每个节点。
        for node_id, node_data in self.__environment.nodes():
            # 使用布尔值 addService 来决定是否添加服务。
            addService = numpy.random.random() <= probability
            # 列出我们可以添加的所有新服务。
            newServices = numpy.setdiff1d(self.__environment.services, node_data.services)
            # 如果我们决定添加服务，并且有新的服务可以添加，则添加它们。
            if addService and len(newServices) > 0:
                newService = random.choice(newServices)
                node_data.services.append(newService)
        return None
    """

    def firewall_change_remove(self, environment: Environment, probability: float = 0.1) -> None:
        # 遍历每个节点。
        for node_id, node_data in environment.nodes():
            # 使用布尔值 remove_rule 来决定是否移除规则。
            remove_rule = numpy.random.random() <= probability
            # 以下逻辑检查是否同时存在入站和出站规则。
            # 如果有，则随机移除一个规则。
            if remove_rule and len(node_data.firewall.outgoing) > 0 and len(node_data.firewall.incoming) > 0:
                incoming = numpy.random.random() <= 0.5
                if incoming:
                    rule_to_remove = random.choice(node_data.firewall.incoming)
                    node_data.firewall.incoming.remove(rule_to_remove)
                else:
                    rule_to_remove = random.choice(node_data.firewall.outgoing)
                    node_data.firewall.outgoing.remove(rule_to_remove)
            # 如果只有出站规则，则移除一个随机的出站规则。
            elif remove_rule and len(node_data.firewall.outgoing) > 0:
                rule_to_remove = random.choice(node_data.firewall.outgoing)
                node_data.firewall.outgoing.remove(rule_to_remove)
            # 如果只有入站规则，则移除一个随机的入站规则。
            elif remove_rule and len(node_data.firewall.incoming) > 0:
                rule_to_remove = random.choice(node_data.firewall.incoming)
                node_data.firewall.incoming.remove(rule_to_remove)

    def firewall_change_add(self, environment: Environment, probability: float = 0.1) -> None:
        # 遍历每个节点。
        for node_id, node_data in environment.nodes():
            # 使用布尔值 rule_to_add 来决定是否添加规则。
            add_rule = numpy.random.random() <= probability
            if add_rule:
                # 0 表示允许，1 表示阻止。
                rule_to_add = model.FirewallRule(port=random.choice(model.SAMPLE_IDENTIFIERS.ports),
                                                 permission=model.RulePermission.ALLOW)
                # 随机决定是否添加入站或出站规则。
                incoming = numpy.random.random() <= 0.5
                if incoming and rule_to_add not in node_data.firewall.incoming:
                    node_data.firewall.incoming.append(rule_to_add)
                elif not incoming and rule_to_add not in node_data.firewall.incoming:
                    node_data.firewall.outgoing.append(rule_to_add)
