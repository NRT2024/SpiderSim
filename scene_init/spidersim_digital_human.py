import Digital_Human
from . import spidersim_env


class CyberBattleDigital(spidersim_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=Digital_Human.new_environment(),
            **kwargs)
