import sea
from . import spidersim_env


class CyberBattleSea(spidersim_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=sea.new_environment(),
            **kwargs)
