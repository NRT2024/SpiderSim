from ..samples.toyctf import smart_sea
from . import cyberbattle_env


class CyberBattleSea(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=smart_sea.new_environment(),
            **kwargs)