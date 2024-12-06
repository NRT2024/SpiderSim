import os
from camel.agents import ChatAgent
from camel.configs import ZhipuAIConfig
from camel.models import ModelFactory
from camel.types import ModelPlatformType, ModelType
from camel.utils import print_text_animated
import re
import ast

class SceneTopologyDiscussion:
    def __init__(self, api_key, base_url, task, introduce):
        # 设置 API 密钥和 URL 到环境变量
        os.environ["ZHIPUAI_API_KEY"] = api_key
        os.environ["BASE_URL"] = base_url

        # 确保环境变量已设置
        self.api_key = os.getenv("ZHIPUAI_API_KEY")
        self.base_url = os.getenv("BASE_URL")

        if not self.api_key or not self.base_url:
            raise ValueError("API key or Base URL is not set correctly.")

        # 创建模型配置和实例
        model_config = ZhipuAIConfig(temperature=0.1).as_dict()  
        self.model = ModelFactory.create(
            model_platform=ModelPlatformType.ZHIPU,
            model_type=ModelType.GLM_4,
            model_config_dict=model_config,
            api_key=self.api_key,
            url=self.base_url,
        )

        # 定义团队成员及其风格
        self.team = [
            ("需求分析师", "根据分析的需求，生成所有硬件、软件和服务的节点，并详细描述每个节点的功能、位置、性能需求及应用场景。"),
            ("网络架构师", "根据需求分析师提出的网络节点，设计合适的网络架构，描述节点间的连接方式，给出口头描述的网络拓扑图。"),
            ("产品经理", "分析需求分析师提出节点的合理性和完整性，并分析网络架构师设计的合理性，提出优化意见。"),
        ]

        # 初始化 ChatAgent 实例
        self.agents = {name: ChatAgent(system_message=style, model=self.model, output_language="chinese") for name, style in self.team}

        # 初始化任务信息
        self.task = task
        self.introduce = introduce
        self.demand_message = ""
        self.network_message = ""
        self.idea = ""

    # 生成任务提示
    def generate_prompt(self, speaker):
        if speaker == "需求分析师":
            return f"""
            任务:{self.task}
            场景介绍:{self.introduce}
            历史方案：{self.demand_message}
            产品经理的意见：{self.idea}
            请根据智慧海洋场景需求，生成所有硬件、软件、服务的节点。每个节点的功能、位置、性能需求及应用场景描述要尽可能详细。
            """
        elif speaker == "网络架构师":
            return f"""
            任务: 设计合适的网络拓扑结构
            需求分析师提出的网络节点:{self.demand_message}
            产品经理的意见：{self.idea}
            请描述如何将这些节点连接成一个有效的网络。请提供一个口头描述的网络拓扑图，并详细说明每个节点的连接方式和连接类型远程连接。
            """
        elif speaker == "产品经理":
            return f"""
            任务：分析需求分析师提出的节点的合理性、完整性；评估网络架构师设计的合理性。请在分析时，提出可能的改进建议。
            需求分析师提出的网络节点：{self.demand_message}
            网络架构师设计的网络拓扑图：{self.network_message}
            请评估这些设计的合理性，并提出改进建议。具体来说：
            1. 如果某些节点的设计过于粗糙或不够完善，需要进行细化，请指出并给出具体细化建议；
            2. 如果某些节点的设计不符合实际需求，或者不必要，可以考虑删除，请明确指出并说明原因；
            3. 如果当前设计中缺少某些关键节点，导致无法实现预期功能，请建议新增节点，并说明其作用。
            """

    # 讨论循环
    def run_discussion_rounds(self, discussion_rounds=2):
        for round_number in range(discussion_rounds):
            for current_speaker, _ in self.team:
                self.agents[current_speaker].reset()

                # 定义任务提示
                prompt = self.generate_prompt(current_speaker)

                # 获取当前成员的回应并输出
                response = self.agents[current_speaker].step(prompt).msgs[0].content
                print_text_animated(f"\033[32m{current_speaker}\033[0m: {response}\n")

                # 更新消息记录
                if current_speaker == "需求分析师":
                    self.demand_message = response
                elif current_speaker == "网络架构师":
                    self.network_message = response
                elif current_speaker == "产品经理":
                    self.idea = response
        return self.demand_message, self.network_message
    

