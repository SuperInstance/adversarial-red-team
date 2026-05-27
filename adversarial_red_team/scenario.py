"""Attack scenarios — chained, timed, and escalating attack sequences."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Sequence

from .attack import Attack


class EscalationMode(Enum):
    """How a scenario escalates between steps."""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    ESCALATING = "escalating"  # each step increases severity


@dataclass
class ScenarioStep:
    """A single step within an attack scenario."""

    attack: Attack
    delay_seconds: float = 0.0
    label: str = ""
    repeat: int = 1


@dataclass
class ScenarioResult:
    """Outcome of executing a scenario step."""

    step_index: int
    attack: Attack
    response: Any
    success: bool
    elapsed: float


@dataclass
class AttackScenario:
    """A multi-step attack scenario with timing and escalation.

    Use this to model realistic attack chains: reconnaissance →
    exploitation → privilege escalation → exfiltration.

    Attributes:
        name: Human-readable scenario name.
        steps: Ordered list of scenario steps.
        escalation: How steps relate to each other.
        max_concurrent: Maximum parallel attacks (for PARALLEL mode).
        id: Unique scenario identifier.
        description: What this scenario tests.
    """

    name: str
    steps: list[ScenarioStep] = field(default_factory=list)
    escalation: EscalationMode = EscalationMode.SEQUENTIAL
    max_concurrent: int = 4
    id: str = field(default_factory=lambda: f"scenario-{uuid.uuid4().hex[:8]}")
    description: str = ""

    # -- builders --

    def add_step(
        self,
        attack: Attack,
        *,
        delay: float = 0.0,
        label: str = "",
        repeat: int = 1,
    ) -> "AttackScenario":
        """Append a step and return *self* for chaining."""
        self.steps.append(ScenarioStep(attack=attack, delay_seconds=delay, label=label, repeat=repeat))
        return self

    def add_chain(self, attacks: Sequence[Attack], delay_between: float = 0.0) -> "AttackScenario":
        """Add multiple attacks as sequential steps."""
        for i, atk in enumerate(attacks):
            self.add_step(atk, delay=delay_between if i > 0 else 0.0)
        return self

    # -- execution --

    def execute(
        self,
        agent_fn: Any,
        *,
        early_stop: bool = True,
    ) -> list[ScenarioResult]:
        """Run the scenario against an agent function.

        Args:
            agent_fn: Callable accepting an Attack and returning a response.
            early_stop: Stop on first success when escalation is ESCALATING.

        Returns:
            List of results, one per step executed.
        """
        results: list[ScenarioResult] = []

        if self.escalation == EscalationMode.PARALLEL:
            return self._execute_parallel(agent_fn)

        for idx, step in enumerate(self.steps):
            for _ in range(step.repeat):
                if step.delay_seconds > 0:
                    time.sleep(step.delay_seconds)

                t0 = time.monotonic()
                response = agent_fn(step.attack)
                elapsed = time.monotonic() - t0
                success = step.attack.evaluate_response(response)

                results.append(
                    ScenarioResult(
                        step_index=idx,
                        attack=step.attack,
                        response=response,
                        success=success,
                        elapsed=elapsed,
                    )
                )

                if early_stop and success and self.escalation == EscalationMode.ESCALATING:
                    return results

        return results

    def _execute_parallel(self, agent_fn: Any) -> list[ScenarioResult]:
        """Execute steps in parallel (simulated, no threads — just ordered)."""
        results: list[ScenarioResult] = []
        for idx, step in enumerate(self.steps):
            t0 = time.monotonic()
            response = agent_fn(step.attack)
            elapsed = time.monotonic() - t0
            results.append(
                ScenarioResult(
                    step_index=idx,
                    attack=step.attack,
                    response=response,
                    success=step.attack.evaluate_response(response),
                    elapsed=elapsed,
                )
            )
        return results

    # -- helpers --

    @property
    def total_attacks(self) -> int:
        return sum(s.repeat for s in self.steps)

    @property
    def max_severity(self) -> str | None:
        if not self.steps:
            return None
        return max(s.attack.severity for s in self.steps).value

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "escalation": self.escalation.value,
            "max_concurrent": self.max_concurrent,
            "steps": [
                {
                    "attack": s.attack.to_dict(),
                    "delay_seconds": s.delay_seconds,
                    "label": s.label,
                    "repeat": s.repeat,
                }
                for s in self.steps
            ],
            "total_attacks": self.total_attacks,
            "max_severity": self.max_severity,
        }
