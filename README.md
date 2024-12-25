## 📰 **What’s New in SpiderSim?**

### 🏭 **v0.4: Digital Twin Scenario Library** *(2024-12-24)*
A newly released Digital Twin Scenario Library, covering industries such as satellite internet, IoT, and smart agriculture.

For code implementation and design details, please refer to the “Simulating Industrial Digitalization Scenarios” and “AI-Powered Scene Generation for Industrial Digitalization Cybersecurity Simulation“ tutorial.

The scenarios are based on our released Satellite Internet Technology Challenge. We welcome more contributors to share their own scenes!

### 🚀 **v0.3: AI-Powered Scene Automation** *(2024-12-05)*

Introducing **AI-driven scene generation**, enabling automated creation and optimization of industrial digitalization cybersecurity simulation.

------

### 🌍 **v0.2: Theoretical-Level Cybersecurity Simulation for Industries** *(2024-08-24)*

Added support for industrial digitalization simulations and theoretical security evaluations in key sectors like energy and manufacturing.

------

### 🛡️ **v0.1: Deception-Based Cyber Defense Evaluation** *(2024-03-21)*

Launched the platform with support for evaluating deception-based defense techniques, including honeypots and the innovative **Shock Trap**.

------



## 🌟 **Summary**

Welcome to **SpiderSim**! This innovative platform is designed for **cybersecurity research** and **theoretical network modeling**, offering a seamless workflow from **atomic-level theoretical validation** to **AI-driven scene generation**. SpiderSim empowers security researchers and practitioners to rapidly validate cutting-edge technologies and explore industrial digitalization security.

Here’s what SpiderSim brings to the table:

------

### 🛠️ **1. Flexible and Efficient Simulation Framework**

- **Lightweight Design**: Quickly deploy and execute simulations without the need for complex virtualization environments.
- **Modular Architecture**: Combine attack and defense modules with ease, adapting to diverse use cases.
- **Rapid Iteration**: Enables developers and researchers to test and improve scenarios efficiently.

------

### 🛡️ **2. Atomic-Level Attack and Defense Capabilities**

- **Deception Technology Validation**: Supports systematic evaluation of honeypots, decoys, and other deception-based defenses.
- **Shock Trap Innovation**: Leverages vulnerability-based traps to intercept attackers, sever attack paths, and provide strong deterrence.
- **Theoretical Validation**: Explores the applicability and synergies of defense technologies, guiding security deployment.

------

### 🌍 **3. Comprehensive Support for Industrial Digitalization**

- **Industry-Specific Simulation**: Models scenarios in manufacturing, energy, transportation, and other critical sectors.
- **Security Assessment**: Simulates threats and validates defense strategies in industrial digitalization scenarios.

------

### 🤖 **4. AI-Driven Automated Scene Generation**

- **Intelligent Scene Construction**: Automatically generate complex scene topologies using LLMs, saving significant time.
- **Dynamic Optimization**: Adjust and refine scenes with AI to improve efficiency and quality.
- **Versatile Applications**: From Smart Ocean to smart manufacturing, supports a wide range of industrial scenarios.

------

### 📊 **5. Experimental Validation and Data-Driven Insights**

- **Attacker Behavior Simulation**: Analyze the impact of defense techniques on attacker behavior using reinforcement learning and random agents.
- **Data-Driven Decision Making**: Provide quantitative metrics to evaluate the effectiveness of defense technologies.
- **Collaborative Research**: Bridges the gap between academic research and real-world engineering applications.



# 🚀 **Getting Started**

### Environment Setup

1. Clone the repository:

   ```
   git clone https://github.com/NRT2024/SpiderSim.git
   cd SpiderSim
   ```

2. Install dependencies:

   ```
   pip install -r requirements.txt
   ```

3. Recommended Python version: **Python 3.10**

------

## 📖 **Functional Overview**

### 1. **Evaluating the Effectiveness of Deception-Based Cyber Defense**

#### **Feature Overview**

SpiderSim provides a simulation environment to evaluate the **effectiveness and applicability of deception-based cybersecurity techniques**. This feature allows users to test honeypots, decoys, and **Shock Trap** in a controlled environment and analyze their impact on attacker behavior.

#### **Development Documentation**

Relevant code file: `cyberbattle/samples/toyctf/toy_ctf.py`

In SpiderSim, **honeypot** and **decoy** techniques simulate fake resource nodes to deceive attackers. Below is an example definition of a honeypot:

```
'Honeypot': m.NodeInfo( 
     services=[m.ListeningService("HTTPS")],
     value=-100,  # Negative reward: attackers are penalized for targeting this node
     properties=["GitHub", "SasUrlInCommit"],
     vulnerabilities=dict(
         ScanGitHistory=m.VulnerabilityInfo(
             description="Some secure access token (SAS) leaked in a reverted git commit",
             type=m.VulnerabilityType.REMOTE,
             precondition=m.Precondition('SasUrlInCommit&GitHub'),
             outcome=m.LeakedCredentials(credentials=[
                         m.CachedCredential(node="AzureStorage",
                                                 port="HTTPS",
                                                 credential="SASTOKEN")]),  # Fake credential
             reward_string="CredScan success: Some secure access token (SAS) was leaked in a reverted git commit",
             cost=1.0,
         )
     )
)
```

In this example:

- The **`value`** is set to negative (-100), meaning attackers are penalized for attacking this node.
- A fake key (`SASTOKEN`) is embedded in the honeypot. If attackers use the key to connect to other network nodes, they are further penalized.

**Decoys** are similar to honeypots but are less complex and do not use fake credentials. Here is an example definition of a decoy node:

```
'Decoys': m.NodeInfo( 
     services=[m.ListeningService("HTTPS", allowedCredentials=["SASTOKEN1"])],
     value=-100,
     properties=["CTFFLAG:LeakedData"],
)
```

Additionally, honeypots and decoys can be referenced in the **`Website`** node, as shown below:

```
IntoHoneypot = m.VulnerabilityInfo(
     description="This is a fake vulnerability connecting to Honeypot",
     type=m.VulnerabilityType.REMOTE,
     outcome=m.LeakedNodesId(["Honeypot"]),
     reward_string="welcome to Honeypot",
     cost=1.0
 )

IntoDecoys = m.VulnerabilityInfo(
     description="This is a fake vulnerability connecting to Decoys",
     type=m.VulnerabilityType.REMOTE,
     outcome=m.LeakedNodesId(["SASTOKEN1"]),
     reward_string="welcome to Decoys",
     cost=1.0
 )
```

These definitions deploy honeypots and decoys on a `Website` node, simulating fake resources attackers might target.

In contrast, **Shock Trap** is designed to act as a deceptive trap triggered by vulnerabilities. It blocks subsequent attack paths and penalizes attackers. Below is an example definition:

```
'Servers': m.NodeInfo(
    services=[m.ListeningService("SSH", allowedCredentials=["ServersCredential"])],
    value=-100,
)
```

In this definition:

- Attackers attempting to connect to this node are penalized and denied further access.

Using the `toy_ctf.py` file, you can simulate a variety of deception-based defense techniques, including honeypots, decoys, and Shock Trap.

#### **Reproducing Results**

After defining the defense techniques, run the following Jupyter Notebook to reproduce the relevant experimental results:

```
notebooks/notebook_benchmark-toyctf.ipynb
```

This script will help you replicate the results published in the [paper](https://link.springer.com/chapter/10.1007/978-3-031-56583-0_15) and validate the effectiveness of deception-based defense techniques.

------

### 2. **Simulating Industrial Digitalization Scenarios**

#### **Feature Overview**

SpiderSim enables **theoretical simulations of industrial digitalization scenarios**, allowing users to generate theoretical-Level simulation environments and analyze their cybersecurity.

#### **Code Example**

For instance, SpiderSim provides a simulation of the **Smart Ocean** scenario. Relevant code can be found here: `cyberbattle/samples/toyctf/smart_sea.py`.

#### **Steps to Run the Simulation**

1. Launch the Jupyter Notebook:

   ```
   notebooks/toyctf-random.ipynb
   ```

2. In the notebook, create a `gym` environment and specify the industrial digitalization scenario:

   ```
   gym_env = gym.make('CyberBattleSea-v0')
   ```

3. Set the `gym_env` parameter to `'CyberBattleSea-v0'` and execute the notebook to build the scenario.

------

### 3. **AI-Powered Scene Generation for Industrial Digitalization Cybersecurity Simulation**

#### **Feature Overview**

SpiderSim integrates **LLMs** to automate the creation of complex industrial digitalization cybersecurity simulation scenarios, significantly simplifying the process of scenario building.

#### **Documentation**

Here are the steps to generate AI-driven industrial digitalization scenarios, using the **Smart Ocean** scenario as an example:

1. **Prepare the Scene Description**
   Edit the file `AI_Scene_Code_Generate/data.txt` to include detailed information about the Smart Ocean scenario. This file serves as the input for scene generation.

   Notice: If the topology of additional scenarios needs to be generated, please include or modify the corresponding scene details accordingly.

2. **Run AI Scene Generation**
   The AI generation code is located in the `AI_Scene_Code_Generate` directory. Configure API keys for the LLM in the `main.py` file or via environment variables, then run:

   ```
   python SpiderSim/AI_Scene_Code_Generate/main.py
   ```

   The generated scene topology will be saved in the `AI_Code/` directory as `AI_Code.json`.

3. **Validate the Generated Scene**
   The following code will read the content of the `AI_Code.json` file and construct the topology of the scene:

   ```
   python cyberbattle/samples/AI_Scene/scene.py
   ```

4. **Instantiate the Scene**
   Create a new file for scene instantiation, For details, refer to`cyberbattle/_env/cyberbattle_ai.py`, and add the following code to the `cyberbattle/__init__.py` file. You can customize the related parameters as needed:

   ```python
   if 'CyberBattleAI-v0' in registry.env_specs:
       del registry.env_specs['CyberBattleAI-v0']
   
   register(
       id='CyberBattleAI-v0',
       cyberbattle_env_identifiers=scene.ENV_IDENTIFIERS,
       entry_point='cyberbattle._env.cyberbattle_ai:CyberBattleAI',
       kwargs={'defender_agent': None,
               'attacker_goal': AttackerGoal(own_atleast=6),
               'defender_goal': DefenderGoal(eviction=True),
               'maximum_total_credentials': 20,
               'maximum_node_count': 30
               },
       max_episode_steps=2600,
   )
   ```

   Additionally, you can use a Jupyter Notebook for further verification:

   ```
   python notebooks/toyctf-random.ipynb
   ```
   
#### **Note**

AI-generated code may contain errors. It is recommended to manually inspect and correct the generated code before integrating it into your project. Alternatively, modify the `scene.py` script to handle generated code manually.

------

## 📚 **Citing SpiderSim**

If you wish to reference SpiderSim in your research, please use the following BibTeX entry:

```
@inproceedings{li2022space,
  title={Space spider: a hyper large scientific infrastructure based on digital twin for the space internet},
  author={Li, Jiaqi and Zhang, Lvyang and Hong, Quan and Yu, Yang and Zhai, Lidong},
  booktitle={Proceedings of the 1st Workshop on Digital Twin \& Edge AI for Industrial IoT},
  pages={31--36},
  year={2022}
}
```

------

## 🤝 **Contribution Guidelines**

We welcome all forms of contributions, including but not limited to:

- **Reporting Issues**: Submit an issue on the GitHub Issues page.
- **Suggesting Features**: Submit a feature request or pull request.
- **Contributing Code**: Fork the repository, create a branch, make your changes, and submit a pull request.

### Before submitting code, please ensure:

1. Your code adheres to the project’s coding standards.
2. Documentation and relevant tests are included.

Thank you for helping us improve SpiderSim!

------

## 🛠️ **Acknowledgments**

- SpiderSim is built on the foundation of Microsoft’s [CyberBattleSim](https://github.com/microsoft/CyberBattleSim). We chose CyberBattleSim as the basis for the early versions of SpiderSim due to its well-structured framework and its suitability for peer review and community collaboration. Thanks to [CyberBattleSim](https://github.com/microsoft/CyberBattleSim).

------

## 📩 **Contact Us**

If you need assistance, feel free to contact us through the following channels:

- Open an issue on the GitHub Issues page.
- Send an email to spidersimnrt@gmail.com.
