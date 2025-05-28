from ..samples.toyctf import sizhong
from . import cyberbattle_env


class CyberBattleSizhong(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=sizhong.new_environment(),
            **kwargs)
