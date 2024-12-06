from openai import OpenAI
import re
import ast

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
        任务：根据需求分析师和网络架构师提供的信息，生成符合指定格式的网络拓扑字典。确保每个节点都能按照要求生成连接方式，并在必要时生成连接密码。连接关系应标明为“local”或“remote”。对于没有子节点的节点，字典应为空字典。如果某个节点在连接中被引用，则该节点也应存在于字典中。
        需求分析师提供的节点:{demand_message}
        网络架构师设计的网络拓扑图:{network_message}

        生成格式要求：
        - 每个节点应作为字典的键（如 "client", "router", "switch", "web" 等）。
        - 每个节点的值应是另一个字典，表示子节点及其连接方式。
        - 如果有子节点，需要指定连接方式（"local" 或 "remote"）并可以为子节点生成连接密码（密码格式为'pw' + 子节点名称，强调：是子节点名称，不是节点名称）,意思是子节点可以有连接密码也可以没有连接密码。
        - 对于没有子节点的节点，字典应为空：{{}}。
        - 如果某个节点在连接中被提到，它也应出现在字典中，保证节点成对出现。
        - 如果某个节点出现在子节点中且该节点未在父节点中定义，需要为该节点添加定义，并保持为空字典“{{}}”。
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
        请只生成python字典，不要生成额外的描述内容，同时字典中每一个节点名称都要明确，不要有抽象名字的节点，例如“所有节点”、“serve”
        请确保输出内容符合这个格式要求，并根据团队的讨论生成合适的节点和连接关系。
        """
        generate_dict = self.code_api(document_engineer_prompt)
        print(generate_dict)
        pattern = re.compile(r'network_topology\s*=\s*(\{.*?\})\s*```', re.DOTALL)
        match = pattern.search(generate_dict)
        # 如果找到匹配的字典部分
        if match:
            dict_str = match.group(1)
            # 使用 ast.literal_eval 安全地转换字符串为字典
            try:
                network_topology = ast.literal_eval(dict_str)
                # print(network_topology)
            except ValueError as e:
                print("解析字典时出错:", e)
        else:
            print("未找到字典内容")
        return network_topology


    def node_code_generate(self, network_topology):
        """根据网络拓扑生成代码片段"""
        code_snippets = []
        # print(network_topology.items())

        for idx, (key, sub_dict) in enumerate(network_topology.items()):
            node_name = key
            vulnerabilities_prompt = ""
            # print("key",key,"sub_dict",sub_dict)
            # 第一个字典的特殊处理
            if idx == 0:
                vulnerabilities_prompt += f"Add parameter: agent_installed=True, reimagable=False,\n"
            
            # 如果子字典为空
            if len(sub_dict)==0:
                vulnerabilities_prompt += f"No 'vulnerabilities' parameter. "
            else:
                # 遍历子字典
                for sub_key, value in sub_dict.items():
                    # print("sub_key:",sub_key,value)
                    if sub_key and value:
                        if isinstance(value, list) and len(value) == 2:
                            # print(sub_key,value[0],value[1])
                            vulnerability_prompt = f"Include vulnerabilities Connect to the sub_node named {sub_key}, The connection way is {value[0]}, The connection password is {value[1]}. Please strictly follow the given sub_node name and do not add any additional strings. "
                        elif isinstance(value, str) and len(value) == 1:
                            # print(sub_key,value)
                            vulnerability_prompt = f"Include vulnerabilities Connect to the sub_node named {sub_key}, The connection way is {value[0]}. Please strictly follow the given sub_node name and do not add any additional strings. "
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
            - NodeID: string (must)
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
            generate_text = self.code_api(prompt_text)
            output_text = re.sub(r"```python\s*|```", "", generate_text)
            print(output_text)
            code_snippets.append(output_text)
        
        return code_snippets

    def code_logic_change(self, code_prompt):
        """修改代码逻辑，根据 LeakedCredentials 更新服务"""
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
        {code_prompt}
        '''

        Expected Output: Provide the entire modified nodes configuration list, where each node's services is updated as specified in the LeakedCredentials.  Ensure all other node attributes and the overall structure of the configuration remain unchanged.

        Task: Focus on updating the services of nodes directly in the provided configurations based on the detailed LeakedCredentials, ensuring accuracy in reflecting the new allowed credentials.
        Please generate the Python code directly inside a `python` code block, without any additional explanatory text or comments outside the code block.
        note: Check the code format to make sure the code is available
        """
        generate_text = self.code_api(prompt_text)
        output_text = re.sub(r"```python\s*|```", "", generate_text)
        return output_text

    def generate_code(self, demand_message, network_message):
        """生成代码并更新逻辑"""
        network_topology = self.generate_topology_dict(demand_message, network_message)
        code_snippets = self.node_code_generate(network_topology)
        output_text = self.code_logic_change(code_snippets)
        # print(output_text)
        return output_text
