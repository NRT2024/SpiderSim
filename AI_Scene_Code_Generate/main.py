from AI_Scene_Generation import SceneTopologyDiscussion
from AI_Code_Generation import NetworkCodeGenerator
import json
import os
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 预定义的示例场景代码，确保在无法调用API时也能返回一个可用的代码
EXAMPLE_SCENE_CODE = '''
"data_center": m.NodeInfo(
    services=[m.ListeningService("SSH", allowedCredentials=["pwdata_center"])],
    value=1000,
    properties=["Linux", "CentOS", "nginx/1.14.0"],
    owned_string="FLAG: Access granted to data_center",
    vulnerabilities=dict(
        RemoteConnection=m.VulnerabilityInfo(
            description="Remote connection to edge_computing_node",
            type=m.VulnerabilityType.REMOTE,
            outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="edge_computing_node", port="SSH", credential="pwedge_computing_node")]),
            reward_string="Successfully connected to edge_computing_node",
            cost=1.0,
        ),
    ),
    agent_installed=True,
    reimagable=False,
),

"edge_computing_node": m.NodeInfo(
    services=[m.ListeningService("SSH", allowedCredentials=["pwedge_computing_node"])],
    value=1000,
    properties=["Ubuntu", "nginx/1.10.3"],
    owned_string="FLAG: Edge computing node successfully compromised",
    vulnerabilities=dict(
        ConnectToEnvironmentalMonitoringBuoy=m.VulnerabilityInfo(
            description="Connect to environmental_monitoring_buoy",
            type=m.VulnerabilityType.LOCAL,
            outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="environmental_monitoring_buoy", port="SSH", credential="pwenvironmental_monitoring_buoy")]),
            reward_string="Successfully connected to environmental_monitoring_buoy",
            cost=1.0,
        ),
    ),
),

"environmental_monitoring_buoy": m.NodeInfo(
    services=[m.ListeningService("SSH", allowedCredentials=["pwenvironmental_monitoring_buoy"])],
    value=1000,
    properties=["IoT", "Linux", "Sensor"],
    owned_string="FLAG: Environmental monitoring buoy has been compromised",
),
'''

# 全局缓存变量，使用示例代码初始化
cached_output = EXAMPLE_SCENE_CODE
# JSON文件路径
AI_CODE_JSON_PATH = "../AI_Code/AI_Code.json"

def scene_generate():
    # 从环境变量获取API密钥和URL
    ZHIPU_API_KEY = os.getenv("ZHIPU_API_KEY")
    ZHIPU_BASE_URL = os.getenv("ZHIPU_BASE_URL")
    TASK = "设计一个智慧海洋场景拓扑图，满足智慧海洋的预期功能"
    INTRODUCE = ""
    try:
        with open("data.txt", "r") as file:
            INTRODUCE = file.read()
    except FileNotFoundError:
        print(f"Error: The file data.txt was not found.")

    # 创建 SceneTopologyDiscussion 实例
    system = SceneTopologyDiscussion(api_key=ZHIPU_API_KEY, base_url = ZHIPU_BASE_URL, task = TASK, introduce = INTRODUCE)

    # 运行讨论回合
    demand_message, network_message = system.run_discussion_rounds()
    return demand_message, network_message

def code_generate(demand_message, network_message):
    # 从环境变量获取API密钥和URL
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
    DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL")

    # 创建 NetworkCodeGenerator 实例
    generator = NetworkCodeGenerator(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL)
    
    # 调用 generate_code 方法生成代码
    output_text = generator.generate_code(demand_message, network_message)
    
    # 将生成的代码保存到JSON文件
    if isinstance(output_text, str):
        # 如果是字符串，则转换为列表
        code_list = output_text.split('\n\n')
    else:
        code_list = output_text
    
    # 保存到JSON文件
    generator.save_to_json(code_list, AI_CODE_JSON_PATH)
    
    return output_text

def get_scene_code():
    """
    生成场景代码，并直接返回结果，可被scene.py调用
    如果已经生成过代码，直接返回缓存的结果
    """
    global cached_output
    
    # 开发过程中设置为True，将使用预定义的示例代码；生产环境设置为False
    use_example_code = False
    
    if use_example_code:
        # 在开发阶段，直接返回示例代码
        # 同时确保示例代码被保存到JSON文件中，以便scene.py调用
        ensure_example_code_saved()
        return cached_output
    
    try:
        # 尝试调用API生成新代码
        demand_message, network_message = scene_generate()
        output_text = code_generate(demand_message, network_message)
        # 缓存结果
        cached_output = output_text
        return output_text
    except Exception as e:
        print(f"Error generating scene code: {e}")
        # 出错时返回预定义的示例代码
        ensure_example_code_saved()
        return cached_output

def ensure_example_code_saved():
    """确保示例代码被保存到JSON文件中"""
    # 检查目录是否存在，如果不存在则创建
    os.makedirs(os.path.dirname(AI_CODE_JSON_PATH), exist_ok=True)
    
    # 检查JSON文件是否存在
    if not os.path.exists(AI_CODE_JSON_PATH):
        # 如果不存在，则创建文件并保存示例代码
        example_code_list = [line.strip() for line in EXAMPLE_SCENE_CODE.split('\n\n') if line.strip()]
        with open(AI_CODE_JSON_PATH, "w") as f:
            json.dump(example_code_list, f)
        print(f"已保存示例代码到 {AI_CODE_JSON_PATH}")

if __name__ == '__main__':
    # 直接生成代码并缓存
    output_text = get_scene_code()
    print("Scene code generation complete.")
    print(f"Generated code length: {len(output_text)}")