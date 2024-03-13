import IOT
from . import spidersim_env


class CyberBattleIOT(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=IOT.new_environment(),
            **kwargs)
