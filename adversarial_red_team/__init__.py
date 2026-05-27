"""Adversarial Red Team — attack simulation and defense testing for AI agents."""

from .attack import Attack, AttackType, Severity
from .scenario import AttackScenario
from .defense import DefenseEvaluator, DefenseResult
from .report import AttackReport, Vulnerability
from .red_team import RedTeamOrchestrator

__version__ = "0.1.0"
__all__ = [
    "Attack",
    "AttackType",
    "Severity",
    "AttackScenario",
    "DefenseEvaluator",
    "DefenseResult",
    "AttackReport",
    "Vulnerability",
    "RedTeamOrchestrator",
]
