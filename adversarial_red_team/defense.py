"""Defense evaluation — measure how well an agent resists attacks."""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any, Sequence

from .attack import Attack, Severity
from .scenario import AttackScenario


@dataclass
class DefenseResult:
    """Result of evaluating a single attack against a defense."""

    attack: Attack
    blocked: bool
    response: Any
    latency_ms: float = 0.0
    notes: str = ""

    @property
    def success(self) -> bool:
        """True when the defense *failed* to block (attack landed)."""
        return not self.blocked


@dataclass
class DefenseEvaluation:
    """Aggregate defense evaluation across multiple attacks."""

    results: list[DefenseResult] = field(default_factory=list)

    def add(self, result: DefenseResult) -> None:
        self.results.append(result)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def blocked_count(self) -> int:
        return sum(1 for r in self.results if r.blocked)

    @property
    def breached_count(self) -> int:
        return sum(1 for r in self.results if not r.blocked)

    @property
    def block_rate(self) -> float:
        """Fraction of attacks that were successfully defended."""
        return self.blocked_count / self.total if self.total else 1.0

    @property
    def breach_rate(self) -> float:
        return 1.0 - self.block_rate

    @property
    def worst_breach(self) -> DefenseResult | None:
        breaches = [r for r in self.results if not r.blocked]
        if not breaches:
            return None
        return max(breaches, key=lambda r: r.attack.severity)

    @property
    def defense_score(self) -> float:
        """0.0 (no defense) to 100.0 (perfect defense), weighted by severity."""
        if not self.results:
            return 100.0
        total_weight = sum(r.attack.severity.weight for r in self.results)
        blocked_weight = sum(
            r.attack.severity.weight for r in self.results if r.blocked
        )
        return (blocked_weight / total_weight) * 100.0 if total_weight else 100.0

    @property
    def avg_latency_ms(self) -> float:
        latencies = [r.latency_ms for r in self.results]
        return statistics.mean(latencies) if latencies else 0.0

    def by_severity(self) -> dict[str, list[DefenseResult]]:
        buckets: dict[str, list[DefenseResult]] = {}
        for r in self.results:
            buckets.setdefault(r.attack.severity.value, []).append(r)
        return buckets

    def to_dict(self) -> dict[str, Any]:
        worst = self.worst_breach
        return {
            "total_attacks": self.total,
            "blocked": self.blocked_count,
            "breached": self.breached_count,
            "block_rate": round(self.block_rate, 4),
            "defense_score": round(self.defense_score, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "worst_breach_severity": worst.attack.severity.value if worst else None,
        }


class DefenseEvaluator:
    """Evaluate how well an agent defends against adversarial attacks.

    Usage::

        evaluator = DefenseEvaluator()
        evaluation = evaluator.evaluate_attacks(
            agent_fn=my_agent,
            attacks=[attack1, attack2],
        )
        print(evaluation.defense_score)
    """

    def __init__(self, latency_threshold_ms: float = 5000.0) -> None:
        self.latency_threshold_ms = latency_threshold_ms

    def evaluate_single(
        self,
        agent_fn: Any,
        attack: Attack,
    ) -> DefenseResult:
        """Send one attack to the agent and record the defense result."""
        import time

        t0 = time.monotonic()
        response = agent_fn(attack)
        elapsed_ms = (time.monotonic() - t0) * 1000.0

        success = attack.evaluate_response(response)
        blocked = not success

        notes = ""
        if elapsed_ms > self.latency_threshold_ms:
            notes = "Response exceeded latency threshold"

        return DefenseResult(
            attack=attack,
            blocked=blocked,
            response=response,
            latency_ms=elapsed_ms,
            notes=notes,
        )

    def evaluate_attacks(
        self,
        agent_fn: Any,
        attacks: Sequence[Attack],
    ) -> DefenseEvaluation:
        """Run a sequence of attacks and return aggregate evaluation."""
        evaluation = DefenseEvaluation()
        for attack in attacks:
            result = self.evaluate_single(agent_fn, attack)
            evaluation.add(result)
        return evaluation

    def evaluate_scenario(
        self,
        agent_fn: Any,
        scenario: AttackScenario,
    ) -> DefenseEvaluation:
        """Evaluate a full attack scenario against an agent."""
        evaluation = DefenseEvaluation()

        def _wrapped(attack: Attack) -> Any:
            result = self.evaluate_single(agent_fn, attack)
            evaluation.add(result)
            return result.response

        scenario.execute(_wrapped)
        return evaluation
