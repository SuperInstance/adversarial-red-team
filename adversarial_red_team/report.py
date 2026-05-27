"""Attack reports — vulnerability scoring, severity classification, remediation."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from .attack import Attack, Severity
from .defense import DefenseEvaluation
from .scenario import ScenarioResult


@dataclass
class Vulnerability:
    """A discovered vulnerability from an attack.

    Attributes:
        title: Short description.
        severity: Impact severity.
        attack_type: Category of the attack that exposed it.
        description: Detailed explanation.
        remediation: How to fix it.
        evidence: Response or data that demonstrates the vulnerability.
        cvss_score: Optional CVSS-style score (0.0–10.0).
    """

    title: str
    severity: Severity
    attack_type: str
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    cvss_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "attack_type": self.attack_type,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
        }


# Severity → CVSS range mapping for auto-scoring
_SEVERITY_CVSS: dict[Severity, tuple[float, float]] = {
    Severity.LOW: (0.1, 3.9),
    Severity.MEDIUM: (4.0, 6.9),
    Severity.HIGH: (7.0, 8.9),
    Severity.CRITICAL: (9.0, 10.0),
}

# Severity → remediation suggestions
_REMEDIATION_HINTS: dict[Severity, str] = {
    Severity.LOW: "Monitor and document. Consider hardening in next release.",
    Severity.MEDIUM: "Implement input validation and output filtering. Add monitoring.",
    Severity.HIGH: "Prioritize fixing before next deployment. Add defense-in-depth controls.",
    Severity.CRITICAL: "Immediate remediation required. Disable affected functionality until patched.",
}


@dataclass
class AttackReport:
    """Comprehensive report from an attack campaign.

    Attributes:
        id: Unique report identifier.
        timestamp: When the report was generated.
        vulnerabilities: List of discovered vulnerabilities.
        evaluation: Defense evaluation summary.
        scenario_results: Raw results from scenario execution.
        metadata: Additional context.
    """

    id: str = field(default_factory=lambda: f"rpt-{uuid.uuid4().hex[:8]}")
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    evaluation: DefenseEvaluation | None = None
    scenario_results: list[ScenarioResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- building --

    def add_vulnerability(
        self,
        attack: Attack,
        response: Any,
        *,
        title: str = "",
        description: str = "",
    ) -> Vulnerability:
        """Create and attach a vulnerability from a successful attack."""
        vuln = Vulnerability(
            title=title or f"{attack.attack_type.value} on {attack.target or 'unknown'}",
            severity=attack.severity,
            attack_type=attack.attack_type.value,
            description=description or attack.description,
            remediation=_REMEDIATION_HINTS.get(attack.severity, ""),
            evidence=str(response)[:500],
            cvss_score=_auto_cvss(attack.severity),
        )
        self.vulnerabilities.append(vuln)
        return vuln

    def build_from_scenario(
        self,
        results: Sequence[ScenarioResult],
    ) -> "AttackReport":
        """Populate the report from scenario results."""
        self.scenario_results = list(results)
        for r in results:
            if r.success:
                self.add_vulnerability(
                    attack=r.attack,
                    response=r.response,
                )
        return self

    def build_from_evaluation(
        self,
        evaluation: DefenseEvaluation,
    ) -> "AttackReport":
        """Populate the report from a defense evaluation."""
        self.evaluation = evaluation
        for r in evaluation.results:
            if not r.blocked:
                self.add_vulnerability(
                    attack=r.attack,
                    response=r.response,
                )
        return self

    # -- analysis --

    @property
    def total_vulnerabilities(self) -> int:
        return len(self.vulnerabilities)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in self.vulnerabilities:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        return counts

    @property
    def overall_risk(self) -> str:
        """High-level risk assessment based on worst vulnerability."""
        if not self.vulnerabilities:
            return "none"
        worst = max(self.vulnerabilities, key=lambda v: v.severity)
        if worst.severity == Severity.CRITICAL:
            return "critical"
        if worst.severity == Severity.HIGH:
            return "high"
        if worst.severity == Severity.MEDIUM:
            return "medium"
        return "low"

    @property
    def avg_cvss(self) -> float:
        if not self.vulnerabilities:
            return 0.0
        return sum(v.cvss_score for v in self.vulnerabilities) / len(
            self.vulnerabilities
        )

    # -- output --

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "total_vulnerabilities": self.total_vulnerabilities,
            "severity_counts": self.severity_counts,
            "overall_risk": self.overall_risk,
            "avg_cvss": round(self.avg_cvss, 2),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "evaluation": self.evaluation.to_dict() if self.evaluation else None,
            "scenario_summary": {
                "total_steps": len(self.scenario_results),
                "successful_attacks": sum(
                    1 for r in self.scenario_results if r.success
                ),
            },
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def summary(self) -> str:
        lines = [
            f"=== Attack Report {self.id} ===",
            f"Timestamp : {self.timestamp}",
            f"Risk      : {self.overall_risk.upper()}",
            f"Vulns     : {self.total_vulnerabilities}",
        ]
        for sev, count in sorted(self.severity_counts.items()):
            lines.append(f"  {sev}: {count}")
        if self.evaluation:
            lines.append(f"Def Score : {self.evaluation.defense_score:.1f}/100")
            lines.append(f"Block Rate: {self.evaluation.block_rate:.1%}")
        lines.append(f"Avg CVSS  : {self.avg_cvss:.1f}")
        if self.vulnerabilities:
            lines.append("")
            lines.append("Top Vulnerabilities:")
            for v in sorted(
                self.vulnerabilities, key=lambda x: x.cvss_score, reverse=True
            )[:5]:
                lines.append(
                    f"  [{v.severity.value.upper():8s}] {v.title} (CVSS {v.cvss_score:.1f})"
                )
                if v.remediation:
                    lines.append(f"             → {v.remediation}")
        return "\n".join(lines)


def _auto_cvss(severity: Severity) -> float:
    """Generate a deterministic CVSS score from severity."""
    lo, hi = _SEVERITY_CVSS[severity]
    return round((lo + hi) / 2, 1)
