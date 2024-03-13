# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import toy_ctf
from . import spidersim_env


class CyberBattleToyCtf(spidersim_env.CyberBattleEnv):
    """CyberBattle simulation based on a toy CTF exercise"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=toy_ctf.new_environment(),
            **kwargs)
