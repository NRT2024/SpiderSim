from numpy import ndarray
from cyberbattle._env import cyberbattle_env
import numpy as np
from typing import List, NamedTuple, Optional, Tuple, Union
import random

# deep learning packages
from torch import Tensor
import torch.nn.functional as F
import torch.optim as optim
import torch.nn as nn
import torch
from torch.distributions import Categorical
from torch.utils.data import DataLoader
from torch.nn.utils.clip_grad import clip_grad_norm_
from torch.distributions import Categorical

from .learner import Learner
from .agent_wrapper import EnvironmentBounds
import cyberbattle.agents.baseline.agent_wrapper as w
from .agent_randomcredlookup import CredentialCacheExploiter
from dataclasses import dataclass, field
from torch.utils.tensorboard import SummaryWriter


device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class CyberBattleStateActionModel:
    """ Define an abstraction of the state and action space
        for a CyberBattle environment, to be used to train a Q-function.
    """

    def __init__(self, ep: EnvironmentBounds):
        self.ep = ep

        self.global_features = w.ConcatFeatures(ep, [
            # w.Feature_discovered_node_count(ep),
            # w.Feature_owned_node_count(ep),
            w.Feature_discovered_notowned_node_count(ep, None)

            # w.Feature_discovered_ports(ep),
            # w.Feature_discovered_ports_counts(ep),
            # w.Feature_discovered_ports_sliding(ep),
            # w.Feature_discovered_credential_count(ep),
            # w.Feature_discovered_nodeproperties_sliding(ep),
        ])

        self.node_specific_features = w.ConcatFeatures(ep, [
            # w.Feature_actions_tried_at_node(ep),
            w.Feature_success_actions_at_node(ep),
            w.Feature_failed_actions_at_node(ep),
            w.Feature_active_node_properties(ep),
            w.Feature_active_node_age(ep)
            # w.Feature_active_node_id(ep)
        ])

        self.state_space = w.ConcatFeatures(ep, self.global_features.feature_selection +
                                            self.node_specific_features.feature_selection)

        self.action_space = w.AbstractAction(ep)
        # print("Global features size:", self.global_features.dim_sizes)
        # print("Node specific features size:", self.node_specific_features.dim_sizes)
        # print("Total features size:", self.state_space.dim_sizes)

    def get_state_astensor(self, state: w.StateAugmentation):
        state_vector = self.state_space.get(state, node=None)
        state_vector_float = np.array(state_vector, dtype=np.float32)
        state_tensor = torch.from_numpy(state_vector_float).unsqueeze(0)
        return state_tensor

    def implement_action(
            self,
            wrapped_env: w.AgentWrapper,
            actor_features: ndarray,
            abstract_action: np.int32) -> Tuple[str, Optional[cyberbattle_env.Action], Optional[int]]:
        """Specialize an abstract model action into a CyberBattle gym action.

            actor_features -- the desired features of the actor to use (source CyberBattle node)
            abstract_action -- the desired type of attack (connect, local, remote).

            Returns a gym environment implementing the desired attack at a node with the desired embedding.
        """

        observation = wrapped_env.state.observation

        # Pick source node at random (owned and with the desired feature encoding)
        potential_source_nodes = [
            from_node
            for from_node in w.owned_nodes(observation)
            if np.all(actor_features == self.node_specific_features.get(wrapped_env.state, from_node))
        ]

        if len(potential_source_nodes) > 0:
            source_node = np.random.choice(potential_source_nodes)

            gym_action = self.action_space.specialize_to_gymaction(
                source_node, observation, np.int32(abstract_action))

            if not gym_action:
                return "exploit[undefined]->explore", None, None

            elif wrapped_env.env.is_action_valid(gym_action, observation['action_mask']):
                return "exploit", gym_action, source_node
            else:
                return "exploit[invalid]->explore", None, None
        else:
            return "exploit[no_actor]->explore", None, None


class Transition(NamedTuple):
    state: Union[Tuple[Tensor], List[Tensor]]
    action: Union[Tuple[Tensor], List[Tensor]]
    next_state: Union[Tuple[Tensor], List[Tensor]]
    reward: Union[Tuple[Tensor], List[Tensor]]


def print_weight_stats(module, name):
    for param_tensor in module.state_dict():
        tensor = module.state_dict()[param_tensor]
        print(f"{name}.{param_tensor} - "
              f"Min: {tensor.min().item()}, "
              f"Max: {tensor.max().item()}, "
              f"Mean: {tensor.mean().item()}, "
              f"Std: {tensor.std().item()}")

class PolicyNetwork(nn.Module):
    def __init__(self, ep: EnvironmentBounds):
        super(PolicyNetwork, self).__init__()

        model = CyberBattleStateActionModel(ep)
        linear_input_size = len(model.state_space.dim_sizes)
        output_size = model.action_space.flat_size()

        self.hidden_layer1 = nn.Linear(linear_input_size, 1024)
        self.bn1 = nn.BatchNorm1d(256)
        self.hidden_layer2 = nn.Linear(1024, 512)
        self.hidden_layer3 = nn.Linear(512, 128)
        self.hidden_layer4 = nn.Linear(128, 64)
        self.head = nn.Linear(64, output_size)

    # Called with either one element to determine next action, or a batch
    # during optimization. Returns tensor([[left0exp,right0exp]...]).
    def forward(self, x):
        x = F.relu(self.hidden_layer1(x))
        x = F.dropout(x, p=0.5, training=self.training)
        x = F.relu(self.hidden_layer2(x))
        x = F.dropout(x, p=0.5, training=self.training)
        x = F.relu(self.hidden_layer3(x))
        x = F.relu(self.hidden_layer4(x))
        return self.head(x.view(x.size(0), -1))



class ValueNetwork(nn.Module):
    def __init__(self, ep: EnvironmentBounds):
        super(ValueNetwork, self).__init__()

        model = CyberBattleStateActionModel(ep)
        linear_input_size = len(model.state_space.dim_sizes)

        self.hidden_layer1 = nn.Linear(linear_input_size, 1024)
        self.hidden_layer2 = nn.Linear(1024, 512)
        self.hidden_layer3 = nn.Linear(512, 128)
        self.head = nn.Linear(128, 1)  # 修改这里，输出一个单独的值

    def forward(self, x):
        x = F.relu(self.hidden_layer1(x))
        x = F.relu(self.hidden_layer2(x))
        x = F.relu(self.hidden_layer3(x))
        return self.head(x.view(x.size(0), -1))  # 输出单个状态值


        


def random_argmax(array):
    max_value = np.max(array)
    max_index = np.where(array == max_value)[0]
    if max_index.shape[0] > 1:
        max_index = int(np.random.choice(max_index, size=1))
    else:
        max_index = int(max_index)
    return max_value, max_index

@dataclass
class ChosenActionMetadata:
    abstract_action: np.int32
    actor_node: int
    actor_features: np.ndarray
    actor_state: np.ndarray
    log_prob: float = field(default=None)  # 可以在创建后修改

    def __repr__(self) -> str:
        return (f"[abstract_action={self.abstract_action}, actor_node={self.actor_node}, "
                f"actor_features={self.actor_features}, actor_state={self.actor_state}, "
                f"log_prob={self.log_prob}]")

class PPOPolicy(Learner):
    def __init__(self, ep: EnvironmentBounds, gamma: float, learning_rate: float, num_steps: int, num_epochs: int, batch_size: int, clip_param: float):
        super(PPOPolicy, self).__init__()
        self.stateaction_model = CyberBattleStateActionModel(ep)
        self.gamma = gamma
        self.learning_rate = learning_rate
        self.num_steps = num_steps
        self.num_epochs = num_epochs
        self.batch_size = batch_size
        self.clip_param = clip_param

        self.policy_net = PolicyNetwork(ep).to(device)
        self.value_net = ValueNetwork(ep).to(device)

        self.optimizer = optim.Adam(list(self.policy_net.parameters()) + list(self.value_net.parameters()), lr=learning_rate)

        self.credcache_policy = CredentialCacheExploiter()
        self.trajectory = []
        self.max_trajectory_length=num_steps
        

    def parameters_as_string(self):
        return f'γ={self.gamma}, lr={self.learning_rate}, num_steps={self.num_steps}, num_epochs={self.num_epochs}, batch_size={self.batch_size}, clip_param={self.clip_param}'

    def all_parameters_as_string(self) -> str:
        model = self.stateaction_model
        return f'{self.parameters_as_string()}\n' \
               f'dimension={model.state_space.flat_size()}x{model.action_space.flat_size()}, ' \
               f'Policy output dimension={self.policy_net.policy_head.out_features}, ' \
               f'Value output dimension=1, ' \
               f"Action space='abstract_action'"

    def lookup_ppo(self, states_to_consider: List[ndarray]) -> Tuple[List[int], List[float]]:
        with torch.no_grad():
            states_to_consider = np.array(states_to_consider, dtype=np.float32)
            state_batch = torch.tensor(states_to_consider, dtype=torch.float32).to(device)
            # print("state_batch",state_batch)
            logits = self.policy_net(state_batch)
        
            # 使用softmax函数确保概率分布有效
            action_probs = F.softmax(logits, dim=-1)
        
            if torch.isnan(action_probs).any():
                print("在action_probs中检测到NaN，采用均匀随机行动。")
                num_actions = action_probs.shape[-1]
                actions = torch.randint(0, num_actions, (action_probs.size(0),), device=device)
                log_probs = -torch.log(torch.tensor([1.0 / num_actions] * actions.size(0), device=device))
            else:
                dist = Categorical(probs=action_probs)
                actions = dist.sample()
                log_probs = dist.log_prob(actions)
    
            action_lookups = actions.cpu().numpy().tolist()
            log_prob_lookups = log_probs.cpu().numpy().tolist()
    
            return action_lookups, log_prob_lookups

    
    def optimize_model(self, training_epochs=10):  # 可以自定义迭代次数
        if not self.trajectory:
            print("没有有效的轨迹可用于训练。")
            return
    
        # 过滤掉包含 None 的 log_probs
        filtered_trajectory = [(state, action, reward, log_prob) for state, action, reward, log_prob in self.trajectory if log_prob is not None]
    
        if not filtered_trajectory:
            print("所有轨迹都包含无效数据。")
            return
    
        # 计算优势和回报
        advantages, returns = self.compute_advantages(filtered_trajectory, self.value_net, self.gamma)
    
        # 转换为Tensor
        states, actions, _, old_log_probs = zip(*filtered_trajectory)
        states_tensor = torch.tensor(states, dtype=torch.float32).to(device)
        actions_tensor = torch.tensor(actions, dtype=torch.long).to(device)
        old_log_probs_tensor = torch.tensor(old_log_probs, dtype=torch.float32).to(device)
    
        # 训练模型多个epoch
        for _ in range(self.num_epochs):
            action_probs = self.policy_net(states_tensor)
            action_probs = F.softmax(action_probs, dim=-1)
            dist = Categorical(action_probs)
            new_log_probs = dist.log_prob(actions_tensor)
    
            ratios = torch.exp(new_log_probs - old_log_probs_tensor)
            surr1 = ratios * advantages
            surr2 = torch.clamp(ratios, 1.0 - self.clip_param, 1.0 + self.clip_param) * advantages
            policy_loss = -torch.min(surr1, surr2).mean()
            value_loss = F.mse_loss(self.value_net(states_tensor).squeeze(), returns)
            loss = policy_loss + 0.5 * value_loss - 0.01 * dist.entropy().mean()
    
            # 反向传播
            self.optimizer.zero_grad()
            loss.backward()
            self.optimizer.step()
    
            # print(f"训练周期 {_ + 1}: 损失 {loss.item()}")
    
    
            # print("训练完成，损失：", loss.item())
            # print("策略损失：", policy_loss.item(), "价值损失：", value_loss.item(), "熵项：", dist.entropy().mean().item())


        
    def compute_advantages(self, trajectory, value_net, gamma, gae_lambda=0.95):
        states, actions, rewards, log_probs = zip(*trajectory)
        states_tensor = torch.tensor(states, dtype=torch.float32).to(device)
        rewards_tensor = torch.tensor(rewards, dtype=torch.float32).to(device)
    
        # 获取价值估计
        values = value_net(states_tensor).detach().squeeze()
        deltas = rewards_tensor + gamma * torch.cat([values[1:], torch.tensor([0.], device=device)]) - values
        advantages = []
        advantage = 0.0
    
        for delta in reversed(deltas):
            advantage = delta + gamma * gae_lambda * advantage
            advantages.insert(0, advantage)
    
        # 将 advantages 列表转换为张量
        advantages_tensor = torch.tensor(advantages, dtype=torch.float32).to(device)
        # 归一化优势值
        advantages_tensor = (advantages_tensor - advantages_tensor.mean()) / (advantages_tensor.std() + 1e-10)
        # print("Normalized advantages tensor:", advantages_tensor)

        # 计算回报
        returns_tensor = advantages_tensor + values.cpu()  # 注意将 values 转到 CPU 并与 advantages_tensor 相加
        # print("returns_tensor",returns_tensor)
    
        return advantages_tensor, returns_tensor






    def get_actor_state_vector(self, global_state, actor_features):
        if isinstance(global_state, np.ndarray):
            global_state = torch.from_numpy(global_state).float().to(device)
        if isinstance(actor_features, np.ndarray):
            actor_features = torch.from_numpy(actor_features).float().to(device)
        if global_state.dim() == 1:
            global_state = global_state.unsqueeze(0)
        if actor_features.dim() == 1:
            actor_features = actor_features.unsqueeze(0)
        combined = torch.cat((global_state, actor_features), dim=-1)
        return combined.cpu().numpy().astype(np.float32)

    def on_step(self, wrapped_env: w.AgentWrapper, observation, reward: float, done: bool, info, action_metadata):
        agent_state = wrapped_env.state
        current_global_state = self.stateaction_model.global_features.get(wrapped_env.state, node=None)
        
        actor_features = self.stateaction_model.node_specific_features.get(wrapped_env.state, action_metadata.actor_node)
        
        actor_state_tensor = self.get_actor_state_vector(current_global_state, actor_features)
        
        log_prob = action_metadata.log_prob
        action = action_metadata.abstract_action
        self.trajectory.append((actor_state_tensor, action, reward, log_prob))
        
        if done or len(self.trajectory) >= self.max_trajectory_length:
            self.optimize_model()
            # print("self.trajectory", self.trajectory)
            # Clear the current trajectory to start fresh for the next episode or batch of steps
            self.trajectory.clear()

        


    def metadata_from_gymaction(self, wrapped_env, gym_action, log_prob=None):
        # 从包裹的环境中获取当前全局状态的特征
        current_global_state = self.stateaction_model.global_features.get(wrapped_env.state, node=None)
        
        # 从 gym 动作中获取执行动作的源节点
        actor_node = cyberbattle_env.sourcenode_of_action(gym_action)
        
        # 获取该源节点的特征
        actor_features = self.stateaction_model.node_specific_features.get(wrapped_env.state, actor_node)
        
        # 将 gym 动作转换为抽象动作
        abstract_action = self.stateaction_model.action_space.abstract_from_gymaction(gym_action)
        
        # 创建并返回 ChosenActionMetadata 对象，包含抽象动作、源节点、节点特征、节点状态以及动作的 log 概率
        return ChosenActionMetadata(
            abstract_action=abstract_action,
            actor_node=actor_node,
            actor_features=actor_features,
            actor_state=self.get_actor_state_vector(current_global_state, actor_features),
            log_prob=log_prob
        )


    def explore(self, wrapped_env: w.AgentWrapper) -> Tuple[str, Optional[cyberbattle_env.Action], object]:
        # 采样有效的动作，这里只考虑本地和远程动作（不包括连接动作）
        gym_action = wrapped_env.env.sample_valid_action(kinds=[0, 1, 2])
        if gym_action:
            metadata = self.metadata_from_gymaction(wrapped_env, gym_action)
            return "explore", gym_action, metadata
        else:
            return "explore[failed]", None, None

        
    def exploit(self, wrapped_env, observation):
        current_global_state = self.stateaction_model.global_features.get(wrapped_env.state, node=None)
        
        active_actors_features: List[ndarray] = [
            self.stateaction_model.node_specific_features.get(wrapped_env.state, from_node)
            for from_node in w.owned_nodes(observation)
        ]
        # 从活跃行动者特征中提取唯一的特征集，以避免重复
        unique_active_actors_features: List[ndarray] = list(np.unique(active_actors_features, axis=0))
        # 为每一组可能的节点特征生成行动者状态向量
        candidate_actor_state_vector: List[ndarray] = [
            self.get_actor_state_vector(current_global_state, node_features)
            for node_features in unique_active_actors_features]

         # 使用策略网络来决定每个actor的动作
        action_lookups, log_prob_lookups = [], []
        for state_vector in candidate_actor_state_vector:
            # print("state_vector",state_vector)
            state_tensor = torch.tensor([state_vector], dtype=torch.float32).to(device)
            # print("state_tensor",state_tensor)
            logits = self.policy_net(state_tensor)
            action_probs = F.softmax(logits, dim=-1)
            dist = Categorical(action_probs)
            action = dist.sample().item()
            log_prob = dist.log_prob(torch.tensor([action], device=device)).item()
    
            action_lookups.append(action)
            log_prob_lookups.append(log_prob)
            
            state_tensor = torch.tensor([current_global_state], dtype=torch.float32).to(device)
            # print("action_lookups",action_lookups)
        # 尝试根据策略网络的推荐执行最有希望的动作
        while action_lookups:
            # 选择最大概率的动作
            max_prob_index = log_prob_lookups.index(max(log_prob_lookups))
            actor_index = max_prob_index
            abstract_action = action_lookups[actor_index]
            # print("abstract_action",abstract_action)
            actor_features = active_actors_features[actor_index]
    
            # 尝试将抽象动作映射到具体的gym动作
            gym_action = self.stateaction_model.action_space.specialize_to_gymaction(
                source_node=int(actor_features[0]),  # 假设源节点索引是第一个特征
                observation=observation,
                abstract_action_index=abstract_action
            )
    
            if gym_action:
                metadata = self.metadata_from_gymaction(wrapped_env, gym_action, log_prob_lookups[max_prob_index])
                return "exploit", gym_action, metadata
    
            # 如果动作不可用，移除并尝试下一个最有希望的动作
            action_lookups.pop(max_prob_index)
            log_prob_lookups.pop(max_prob_index)
            active_actors_features.pop(max_prob_index)
    
        return "exploit[failed]->explore", None, None
    


    def stateaction_as_string(self, action_metadata) -> str:
        return ''