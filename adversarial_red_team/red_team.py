"""Red team orchestrator — run full attack campaigns with reporting."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from .attack import Attack, AttackType, Severity
from .defense import DefenseEvaluator, DefenseEvaluation
from .report import AttackReport
from .scenario import AttackScenario, ScenarioResult


@dataclass
class CampaignConfig:
    """Configuration for an attack campaign."""

    name: str = "Unnamed Campaign"
    max_attacks: int = 100
    timeout_seconds: float = 300.0
    stop_on_critical: bool = True
    stop_on_breach_count: int = 0  # 0 = don't stop early
    attack_types: list[AttackType] | None = None  # None = all types
    min_severity: Severity = Severity.LOW
    description: str = ""


@dataclass
class CampaignResult:
    """Result of a completed campaign."""

    config: CampaignConfig
    report: AttackReport
    evaluation: DefenseEvaluation
    duration_seconds: float = 0.0
    attacks_executed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign": self.config.name,
            "duration_seconds": round(self.duration_seconds, 2),
            "attacks_executed": self.attacks_executed,
            "report": self.report.to_dict(),
            "evaluation": self.evaluation.to_dict(),
        }

    def summary(self) -> str:
        lines = [
            f"Campaign: {self.config.name}",
            f"Executed: {self.attacks_executed} attacks in {self.duration_seconds:.1f}s",
        ]
        lines.append(self.report.summary())
        return "\n".join(lines)


class RedTeamOrchestrator:
    """Orchestrate full red-team campaigns against an AI agent.

    Usage::

        orchestrator = RedTeamOrchestrator()
        result = orchestrator.run_campaign(
            agent_fn=my_agent,
            attacks=my_attacks,
            config=CampaignConfig(name="Security Audit"),
        )
        print(result.summary())
    """

    def __init__(self, evaluator: DefenseEvaluator | None = None) -> None:
        self.evaluator = evaluator or DefenseEvaluator()
        self._campaigns: list[CampaignResult] = []

    @property
    def campaigns(self) -> list[CampaignResult]:
        return list(self._campaigns)

    def run_campaign(
        self,
        agent_fn: Callable[..., Any],
        attacks: Sequence[Attack],
        config: CampaignConfig | None = None,
    ) -> CampaignResult:
        """Execute a campaign of attacks against an agent.

        Args:
            agent_fn: Callable accepting an Attack, returning a response.
            attacks: Sequence of attacks to execute.
            config: Campaign configuration.

        Returns:
            CampaignResult with full report and evaluation.
        """
        cfg = config or CampaignConfig()
        t0 = time.monotonic()

        # Filter attacks by config
        filtered = self._filter_attacks(attacks, cfg)
        evaluation = DefenseEvaluation()
        report = AttackReport(
            metadata={"campaign": cfg.name, "description": cfg.description}
        )

        executed = 0
        for attack in filtered:
            if executed >= cfg.max_attacks:
                break
            if (time.monotonic() - t0) > cfg.timeout_seconds:
                break

            # Evaluate
            result = self.evaluator.evaluate_single(agent_fn, attack)
            evaluation.add(result)
            executed += 1

            # Record vulnerability if breached
            if not result.blocked:
                report.add_vulnerability(
                    attack=attack,
                    response=result.response,
                )

                # Early stop checks
                if cfg.stop_on_critical and attack.severity == Severity.CRITICAL:
                    break
                if (
                    cfg.stop_on_breach_count > 0
                    and evaluation.breached_count >= cfg.stop_on_breach_count
                ):
                    break

        report.evaluation = evaluation
        duration = time.monotonic() - t0

        campaign_result = CampaignResult(
            config=cfg,
            report=report,
            evaluation=evaluation,
            duration_seconds=duration,
            attacks_executed=executed,
        )
        self._campaigns.append(campaign_result)
        return campaign_result

    def run_scenario(
        self,
        agent_fn: Callable[..., Any],
        scenario: AttackScenario,
        config: CampaignConfig | None = None,
    ) -> CampaignResult:
        """Execute a scenario against an agent and produce a campaign result."""
        cfg = config or CampaignConfig(name=scenario.name)
        t0 = time.monotonic()

        # Execute scenario
        results = scenario.execute(agent_fn)

        # Evaluate
        evaluation = self.evaluator.evaluate_scenario(agent_fn, scenario)

        # Build report
        report = AttackReport(
            metadata={
                "campaign": cfg.name,
                "scenario_id": scenario.id,
                "description": cfg.description or scenario.description,
            }
        )
        report.build_from_scenario(results)
        report.evaluation = evaluation

        duration = time.monotonic() - t0

        campaign_result = CampaignResult(
            config=cfg,
            report=report,
            evaluation=evaluation,
            duration_seconds=duration,
            attacks_executed=len(results),
        )
        self._campaigns.append(campaign_result)
        return campaign_result

    @staticmethod
    def _filter_attacks(
        attacks: Sequence[Attack], config: CampaignConfig
    ) -> list[Attack]:
        filtered = list(attacks)
        if config.attack_types is not None:
            filtered = [a for a in filtered if a.attack_type in config.attack_types]
        filtered = [
            a for a in filtered if a.severity >= config.min_severity
        ]
        return filtered

    def summary(self) -> str:
        """Summarize all campaigns run by this orchestrator."""
        lines = [f"Red Team Orchestrator — {len(self._campaigns)} campaign(s)"]
        for cr in self._campaigns:
            lines.append("")
            lines.append(f"--- {cr.config.name} ---")
            lines.append(
                f"  Attacks: {cr.attacks_executed} | "
                f"Vulns: {cr.report.total_vulnerabilities} | "
                f"Score: {cr.evaluation.defense_score:.1f}/100"
            )
        return "\n".join(lines)
