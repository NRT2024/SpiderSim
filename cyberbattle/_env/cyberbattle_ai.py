from ..samples.AI_Scene import scene
from . import cyberbattle_env


class CyberBattleAI(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=scene.new_environment(),
            **kwargs)