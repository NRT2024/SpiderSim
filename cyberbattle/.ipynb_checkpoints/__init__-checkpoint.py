# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Initialize CyberBattleSim module"""
from gym.envs.registration import registry, EnvSpec
from gym.error import Error

from . import simulation
from . import agents
from ._env.cyberbattle_env import AttackerGoal, DefenderGoal
from .samples.toyctf import toy_ctf
from .samples.toyctf import smart_sea
from .samples.AI_Scene import scene
from .simulation import model

__all__ = (
    'simulation',
    'agents',
)


def register(id: str, cyberbattle_env_identifiers: model.Identifiers, **kwargs):
    """与 gym.envs.registry.register 相同，但会将 CyberBattle 规格添加到 env.spec"""
    if id in registry.env_specs:
        raise Error('Cannot re-register id: {}'.format(id))
    spec = EnvSpec(id, **kwargs)
    # Map from port number to port names : List[model.PortName]
    spec.ports = cyberbattle_env_identifiers.ports
    # Array of all possible node properties (not necessarily all used in the network) : List[model.PropertyName]
    spec.properties = cyberbattle_env_identifiers.properties
    # Array defining an index for every possible local vulnerability name : List[model.VulnerabilityID]
    spec.local_vulnerabilities = cyberbattle_env_identifiers.local_vulnerabilities
    # Array defining an index for every possible remote  vulnerability name : List[model.VulnerabilityID]
    spec.remote_vulnerabilities = cyberbattle_env_identifiers.remote_vulnerabilities

    registry.env_specs[id] = spec


if 'CyberBattleToyCtf-v0' in registry.env_specs:
    del registry.env_specs['CyberBattleToyCtf-v0']

register(
    id='CyberBattleToyCtf-v0',
    cyberbattle_env_identifiers=toy_ctf.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.cyberbattle_toyctf:CyberBattleToyCtf',
    kwargs={'defender_agent': None,
            'attacker_goal': AttackerGoal(own_atleast=6),
            'defender_goal': DefenderGoal(eviction=True)
            },
    # max_episode_steps=2600,
)

if 'CyberBattleTiny-v0' in registry.env_specs:
    del registry.env_specs['CyberBattleTiny-v0']

register(
    id='CyberBattleTiny-v0',
    cyberbattle_env_identifiers=toy_ctf.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.cyberbattle_tiny:CyberBattleTiny',
    kwargs={'defender_agent': None,
            'attacker_goal': AttackerGoal(own_atleast=6),
            'defender_goal': DefenderGoal(eviction=True),
            'maximum_total_credentials': 10,
            'maximum_node_count': 10
            },
    # max_episode_steps=2600,
)



if 'CyberBattleSea-v0' in registry.env_specs:
    del registry.env_specs['CyberBattleSea-v0']

register(
    id='CyberBattleSea-v0',
    cyberbattle_env_identifiers=smart_sea.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.cyberbattle_smartsea:CyberBattleSea',
    kwargs={'defender_agent': None,
            'attacker_goal': AttackerGoal(own_atleast=6),
            'defender_goal': DefenderGoal(eviction=True),
            'maximum_total_credentials': 10,
            'maximum_node_count': 15
            },
    # max_episode_steps=2600,
)

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
    # max_episode_steps=2600,
)
