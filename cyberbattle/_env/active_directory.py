# SpiderSim - A Network Attack Simulation Environment
# Copyright (c) 2024 NRT

# This project includes code modified from CyberBattle 
# (https://github.com/microsoft/CyberBattleSim/tree/main/cyberbattle) used under Licensed under the MIT License.


from ..samples.active_directory import generate_ad
from . import cyberbattle_env
from ..samples.active_directory import tiny_ad


class CyberBattleActiveDirectory(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation based on real world Active Directory networks"""

    def __init__(self, seed, **kwargs):
        super().__init__(initial_environment=generate_ad.new_random_environment(seed), **kwargs)


class CyberBattleActiveDirectoryTiny(cyberbattle_env.CyberBattleEnv):
    def __init__(self, **kwargs):
        super().__init__(initial_environment=tiny_ad.new_environment(), **kwargs)
