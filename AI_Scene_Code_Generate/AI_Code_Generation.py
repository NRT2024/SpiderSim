from openai import OpenAI
import re
import ast
import json
import os

class NetworkCodeGenerator:
    def __init__(self, api_key, base_url):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        
        
    def code_api(self, prompt_text):
        """请求 OpenAI GPT 模型进行代码生成"""
        response = self.client.chat.completions.create(
            model="deepseek-chat",  # 选择适合的模型
            messages=[
                {"role": "system", "content": "You are a helpful assistant"},
                {"role": "user", "content": prompt_text},
            ],
            temperature=0.0,
        )
        return response.choices[0].message.content

    def generate_topology_dict(self, demand_message, network_message):
        document_engineer_prompt = f"""
        任务：根据需求分析师和网络架构师提供的信息，生成符合指定格式的网络拓扑字典。
        要求：
        1.确保每个节点都能按照要求生成连接方式，并在必要时生成连接密码。连接关系应标明为"local"或"remote"。
        2.对于没有子节点的节点，字典应为空字典。
        3.如果某个节点在连接中被引用，则该节点也应存在于字典中。

        需求分析师提供的节点:{demand_message}
        网络架构师设计的网络拓扑图:{network_message}

        生成格式要求：
        - 每个节点应作为字典的键（如 "client", "router", "switch", "web" 等）。
        - 每个节点的值应是另一个字典，表示子节点及其连接方式。
        - 如果有子节点，需要指定连接方式（"local" 或 "remote"）并可以为子节点生成连接密码（密码格式为'pw' + 子节点名称，强调：是子节点名称，不是节点名称）,意思是子节点可以有连接密码也可以没有连接密码。
        - 对于没有子节点的节点，字典应为空：{{}}。
        - 如果某个节点在连接中被提到，它也应出现在字典中，保证节点成对出现。
        - 如果某个节点出现在子节点中且该节点未在父节点中定义，需要为该节点添加定义，并保持为空字典"{{}}"
        - 生成的节点连接方式中至少包含一个"remote"连接方式和一个"local"连接方式。
        \"\"\"python
        network_topology = {{
            "client": {{
                "router": ["local","pwrouter"],
                "website": ["local","pwwebsite"]
            }},
            "router": {{
                "switch": ["local","pwswitch"],
                "web": "remote"
            }},
            "switch": {{
                "workstation": ["local","pwworkstation"]
            }},
            "web": {{
                "server": ["romote","pwserver"],
            }},
            "server": {{}},
            "workstation": {{}},
            "website": {{}}
        }}
        \"\"\"
        请只生成python字典，不要生成额外的描述内容，同时字典中每一个节点名称都要明确，不要有抽象名字的节点，例如"所有节点"、"serve"
        请确保输出内容符合这个格式要求，并根据团队的讨论生成合适的节点和连接关系。
        """
        # 获取生成的拓扑结构字典文本
        generate_dict = self.code_api(document_engineer_prompt)
        print(generate_dict)
        
        # 从生成的文本中提取Python字典
        try:
            # 提取代码块中的内容，使用字符串处理方法
            if "```python" in generate_dict:
                # 如果包含代码块标记，提取代码块内容
                start_idx = generate_dict.find("network_topology = {")
                end_idx = generate_dict.rfind("}")
                dict_str = generate_dict[start_idx:end_idx+1]
                # 提取赋值语句右侧的字典部分
                dict_str = dict_str.split("=", 1)[1].strip()
            else:
                # 如果没有代码块标记，尝试直接识别字典部分
                start_idx = generate_dict.find("{")
                end_idx = generate_dict.rfind("}")
                dict_str = generate_dict[start_idx:end_idx+1]
            
            # 使用ast.literal_eval安全地解析字典
            network_topology = ast.literal_eval(dict_str)
            return network_topology
        except Exception as e:
            print(f"解析网络拓扑字典时出错: {e}")
            # 返回一个简单的默认拓扑结构
            return {
                "data_center": {
                    "edge_computing_node": ["remote", "pwedge_computing_node"]
                },
                "edge_computing_node": {}
            }

    def node_code_generate(self, network_topology):
        """根据网络拓扑生成代码片段"""
        code_snippets = []

        for idx, (key, sub_dict) in enumerate(network_topology.items()):
            node_name = key
            vulnerabilities_prompt = ""
            
            # 第一个字典的特殊处理
            if idx == 0:
                vulnerabilities_prompt += f"Add parameter: agent_installed=True, reimagable=False,\n"
            
            # 如果子字典为空
            if len(sub_dict) == 0:
                vulnerabilities_prompt += f"No 'vulnerabilities' parameter. "
            else:
                # 遍历子字典
                for sub_key, value in sub_dict.items():
                    if sub_key and value:
                        if isinstance(value, list) and len(value) == 2:
                            vulnerability_prompt = f"Include vulnerabilities Connect to the sub_node named {sub_key}, The connection way is {value[0]}, The connection password is {value[1]}. Please strictly follow the given sub_node name and do not add any additional strings. "
                        elif isinstance(value, str):
                            vulnerability_prompt = f"Include vulnerabilities Connect to the sub_node named {sub_key}, The connection way is {value}. Please strictly follow the given sub_node name and do not add any additional strings. "
                        else:
                            vulnerability_prompt = "Invalid value format."
                        vulnerabilities_prompt += vulnerability_prompt
                    else:
                        vulnerabilities_prompt += "No vulnerabilities parameter."

            # 生成代码的提示文本
            prompt_text = f"""
            Generate a Python code snippet that defines a network node configuration according to the specified parameters. The node should be named "{node_name}" and configured with  attributes and a specific vulnerability. Provide the Python code within a `python` code block.

            Code Requirements:
            - Node Name: "{node_name}"
            - Value: 1000
            - {vulnerabilities_prompt}
            - Other additional must parameters, refer to the explanation of parameters

            Expected Code Output Format:
            Please generate the Python code directly inside a `python` code block, without any additional explanatory text or comments outside the code block.

            Example Code Template:
            \"\"\"python
            "Website": m.NodeInfo(
                    services=[m.ListeningService("HTTPS"), m.ListeningService("SSH", allowedCredentials=["ReusedMySqlCred-web"])],
                    value=100,
                    properties=["MySql", "Ubuntu", "nginx/1.10.3"],
                    owned_string="FLAG: Login using insecure SSH user/password",
                    vulnerabilities=dict(
                        ScanPageContent=m.VulnerabilityInfo(
                            description="LeakedGitHubProjectUrl: Website page content shows a link to GitHub " "repo",
                            type=m.VulnerabilityType.REMOTE,
                            outcome=m.LeakedNodesId(["GitHubProject"]),
                            reward_string="WEBSITE page content has a link to github -> Github project discovered!",
                            cost=1.0,
                        ),
                        CredScanBashHistory=m.VulnerabilityInfo(
                            description="bash history leaking creds - FLAG Stealing " "credentials for the monitoring user",
                            type=m.VulnerabilityType.LOCAL,
                            outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="Website[user=monitor]", port="SSH", credential="monitorBashCreds")]),
                            reward_string="FLAG: SSH history revealed credentials for the monitoring user (monitor)",
                            cost=1.0,
                        ),
                    ),
                ),
            \"\"\"

            Fill in the Template with Details:
            - NodeID: string (must)  This parameter is the key value of the dictionary. Refer to "Website" in the above example. It must be wrapped by "".
            - services: m.ListeningService("") One of a random list ["RDP","SSH","HTTPS","HTTP"]
            - value:  Intrinsic value of the node (translates into a reward if the node gets owned) (must)
            - properties: Properties of the nodes, some of which can imply further vulnerabilities (optional)
            - owned_string: String displayed when the node gets owned (must)
            - vulnerabilities: Node connected to the sub_node ,If the word "No 'vulnerabilities' parameter" appears in the prompt,that parameter is not needed
                -- description: an optional description of what the vulnerability is (optional)
                -- type: Connection type, local or remote connection (optional)
                -- outcome: Connect to the next node LeakedNodesId or LeakedCredentials with credentials, port, credential. If the connected node has a password, the content of the outcome is m LeakedCredentials (credentials=[m. CachedCredential (node="{sub_key}", port="", credential="")]) The value of the credential attribute is the password mentioned in the prompt, with a port parameter of One of a random list ["RDP", "SSH", "HTTPS", "HTTP"],otherwise the outcome content is m.LeakedNodesId (["{sub_key}"])
                -- reward_string: a string displayed when the vulnerability is successfully exploited (optional)
                -- cost=1.0 (optional)
            """
            # 获取生成的代码文本
            generate_text = self.code_api(prompt_text)
            
            # 提取代码块内容，使用简单的字符串处理
            if "```python" in generate_text:
                # 提取代码块中的内容
                code_block = generate_text.split("```python", 1)[1]
                if "```" in code_block:
                    code_block = code_block.split("```", 1)[0]
            else:
                # 如果没有代码块标记，尝试提取双引号开始的部分（节点定义）
                code_block = generate_text.strip()
                
            print(code_block)
            code_snippets.append(code_block.strip())
        
        return code_snippets

    def code_logic_change(self, code_snippets):
        """修改代码逻辑，根据 LeakedCredentials 更新服务"""
        # 将代码片段合并成一个字符串
        combined_code = "\n".join(code_snippets)
        
        prompt_text = f"""
        Prompt: Directly modify the Python code snippet provided, updating only the services attributes of specific nodes that are mentioned in the LeakedCredentials within the vulnerabilities of other nodes. Each node affected by LeakedCredentials should have its services updated to include the new credentials on the specified ports, reflecting the changes accurately while preserving the formatting and details of the original input.

        Example: If the vulnerabilities of a node result in leaked credentials as follows:
        outcome=m.LeakedCredentials(credentials=[
            m.CachedCredential(node="router", port="SSH", credential="pwrouter"),
            m.CachedCredential(node="website", port="HTTP", credential="pwwebsite")
        ])
        then directly update the input configuration for:

        Node "router" from:
        services=[m.ListeningService("SSH")]
        to:
        services=[m.ListeningService("SSH", allowedCredentials=["pwrouter"])],
        Node "website" from:
        m.ListeningService("HTTP")
        to:
        services=[m.ListeningService("HTTP", allowedCredentials=["pwwebsite"])],

        Input: 
        '''python
        {combined_code}
        '''

        Expected Output: Provide the entire modified nodes configuration list, where each node's services is updated as specified in the LeakedCredentials.  Ensure all other node attributes and the overall structure of the configuration remain unchanged.

        Task: Focus on updating the services of nodes directly in the provided configurations based on the detailed LeakedCredentials, ensuring accuracy in reflecting the new allowed credentials.
        Please generate the Python code directly inside a `python` code block, without any additional explanatory text or comments outside the code block.
        note: Check the code format to make sure the code is available
        """
        # 获取处理后的代码
        output_text = self.code_api(prompt_text)
        
        # 提取代码块内容
        if "```python" in output_text:
            # 提取代码块中的内容
            code_block = output_text.split("```python", 1)[1]
            if "```" in code_block:
                code_block = code_block.split("```", 1)[0]
            output_text = code_block.strip()
        
        return output_text

    def generate_code(self, demand_message, network_message):
        """生成代码并更新逻辑"""
        network_topology = self.generate_topology_dict(demand_message, network_message)
        if network_topology is None:
            print("Error generating topology dictionary: network_topology is None")
            network_topology = {
                "data_center": {
                    "edge_computing_node": ["remote", "pwedge_computing_node"]
                },
                "edge_computing_node": {}
            }
            
        code_snippets = self.node_code_generate(network_topology)
        output_text = self.code_logic_change(code_snippets)
        return output_text

    def save_to_json(self, code_list, output_path="../AI_Code/AI_Code.json"):
        """保存生成的代码到JSON文件"""
        # 确保目录存在
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # 将代码列表保存到JSON文件
        with open(output_path, "w") as f:
            json.dump(code_list, f)
        
        print(f"已保存生成的代码到 {output_path}")
        return output_path

if __name__ == "__main__":
    # 配置 API 密钥和 URL
    DEEPSEEK_API_KEY = "sk-ffc8bc8699dc47baafaef44fd618774f"  # 在这里填入你的 OpenAI API 密钥
    DEEPSEEK__BASE_URL = "https://api.deepseek.com"  # 在这里填入 DeepSeek API 的 URL（如果有特定的 API URL）

    demand_message = """
    根据智慧海洋场景的需求，以下是详细的硬件、软件和服务节点设计，包括其功能、位置、性能需求和应用场景。

### 硬件节点

1. **环境监测浮标**
   - **功能**：实时监测海洋水质（如pH值、溶解氧、营养盐）、水文（如水温、盐度）和气象（如风速、风向、气压）参数。
   - **位置**：分布在海洋牧场的不同区域，确保全面覆盖。
   - **性能需求**：
     - 防水等级IP68，耐腐蚀，适应恶劣海洋环境。
     - 内置GPS，精确位置信息。
     - 数据传输模块，支持4G/5G或卫星通信。
     - 低能耗设计，太阳能板供电，具备电池备份。
   - **应用场景**：
     - 实时监测海洋环境变化，为海洋牧场管理提供数据支持。
     - 预警系统的重要组成部分，用于触发环境异常警告。

2. **生物监测潜水器**
   - **功能**：搭载高清摄像头和声学传感器，进行水下生物种类、数量和健康状况的监测。
   - **位置**：根据监测需求，在特定区域进行潜水作业。"""

    network_message = """
    网络架构师: 以下是根据需求设计的智慧海洋牧场网络拓扑图的口头描述，以及节点间的连接方式和连接类型：

### 网络拓扑图描述

1. **核心层**：
   - **数据中心**：位于陆地上，是整个网络的大脑，包含数据采集与预处理系统、大数据分析平台和智能控制系统。
   - **连接方式**：所有硬件节点通过远程通信方式与数据中心连接。
   - **连接类型**：使用VPN加密的4G/5G网络或卫星通信链路。"""

    # 创建 NetworkCodeGenerator 实例
    generator = NetworkCodeGenerator(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK__BASE_URL)
    
    # 测试 generate_topology_dict 方法
    try:
        # 生成代码
        generated_code = generator.generate_code(demand_message, network_message)
        
        # 将生成的代码转换为列表格式（如果不是列表）
        if not isinstance(generated_code, list):
            code_list = generated_code.split('\n\n')
        else:
            code_list = generated_code
            
        # 保存到JSON文件
        json_path = generator.save_to_json(code_list)
        print(f"代码已成功保存到：{json_path}")
        
    except Exception as e:
        print(f"生成或保存代码时出错: {e}")
        
        # 使用预定义的示例代码作为备选
        example_code = ['"data_center": m.NodeInfo(\n    services=[m.ListeningService("SSH", allowedCredentials=["pwdata_center"])],\n    value=1000,\n    properties=["Ubuntu", "nginx/1.10.3"],\n    agent_installed=True,\n    reimagable=False,\n    owned_string="FLAG: Login using insecure SSH user/password",\n    vulnerabilities=dict(\n        ConnectToEdgeComputingNode=m.VulnerabilityInfo(\n            description="Remote connection to edge_computing_node",\n            type=m.VulnerabilityType.REMOTE,\n            outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="edge_computing_node", port="SSH", credential="pwedge_computing_node")]),\n            reward_string="FLAG: Successfully connected to edge_computing_node",\n            cost=1.0,\n        ),\n    ),\n),\n']
        
        json_path = generator.save_to_json(example_code)
        print(f"使用示例代码保存到：{json_path}")
