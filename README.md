## 📰 **What’s New in SpiderSim?**

### 🏭 **v0.4: Industrial Digitalization Scenario Library** *(2024-12-24)*

A newly released **Industrial Digitalization Scenario Library**, covering industries such as satellite internet, IoT, and smart agriculture. For details, refer to the `Industrial_Digitalization_Scenario_Library` files.

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

## 🌟  **Getting Started**

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

We have defined honeypot spoofing technology in our code.

Relevant code file: `cyberbattle/samples/toyctf/toy_ctf.py`

Run the following Jupyter Notebook to reproduce the relevant experimental results:

```
notebooks/notebook_benchmark-toyctf.ipynb
```

This script will help you replicate the results published in the [paper](https://link.springer.com/chapter/10.1007/978-3-031-56583-0_15) and validate the effectiveness of deception-based defense techniques.

------

### 2. **Simulating Industrial Digitalization Scenarios**

SpiderSim provides a simulation of the **Smart Ocean** scenario. Relevant code can be found here: `cyberbattle/samples/toyctf/smart_sea.py`.

#### **Steps to Run the Simulation**

1. Launch the Jupyter Notebook:

   ```
   notebooks/toyctf-random.ipynb
   ```

2. Set the `gym_env` parameter to `'CyberBattleSea-v0'` and execute the notebook to build the scenario.


------

### 3. **AI-Powered Scene Generation for Industrial Digitalization Cybersecurity Simulation**

Here are the steps to generate AI-driven industrial digitalization scenarios, using the **Smart Ocean** scenario as an example:

1. **Prepare the Scene Description**
   Edit the file `AI_Scene_Code_Generate/data.txt` to include detailed information about the Smart Ocean scenario. This file serves as the input for scene generation.

2. **Run AI Scene Generation**
   The AI generation code is located in the `AI_Scene_Code_Generate` directory. Configure API keys for the LLM in the `main.py` file or via environment variables, then run:

   ```
   python SpiderSim/AI_Scene_Code_Generate/main.py
   ```

   The generated scene topology will be saved in the `AI_Code/` directory as `AI_Code.json`.

3. **Obtain experimental results**

   Run the following Jupyter Notebook, set the `gym_env` parameter to `'CyberBattleAI-v0'`, and execute the notebook to reproduce the relevant experimental results:

   ```
   notebooks/notebook_benchmark-toyctf.ipynb
   ```


Note: AI-generated code may contain errors. It is recommended to manually inspect and correct the generated code before integrating it into your project. Alternatively, modify the `scene.py` script to handle generated code manually.

### Note

The tutorial above provides instructions on running our DAMO project. For more detailed information about the project, please refer to the [comprehensive tutorial]((/img/detailintro.md) ). 

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
