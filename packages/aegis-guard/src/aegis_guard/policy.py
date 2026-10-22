"""Risk Policy implementation for Aegis Guard.

Maps (device, action) tuples to Risk Levels (LOW, MEDIUM, HIGH) loaded from YAML.
Unknown actions default to HIGH (Fail Closed).
"""

from enum import Enum
from pathlib import Path
from typing import Any, Mapping
import yaml
from pydantic import BaseModel, Field

DEFAULT_PROPOSAL_TTL_SECONDS: float = 60.0
PROPOSAL_EXPIRATION_TIMEOUT: float = 60.0


class RiskLevel(str, Enum):
    """Enumeration of risk classifications for smart-home actions."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        ranks = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}
        return ranks[self]

    def __ge__(self, other: "RiskLevel") -> bool:
        if isinstance(other, RiskLevel):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: "RiskLevel") -> bool:
        if isinstance(other, RiskLevel):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: "RiskLevel") -> bool:
        if isinstance(other, RiskLevel):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: "RiskLevel") -> bool:
        if isinstance(other, RiskLevel):
            return self.rank < other.rank
        return NotImplemented


class PolicyRule(BaseModel):
    """Individual rule mapping a device and action to a risk level."""

    device: str
    action: str
    risk: RiskLevel
    description: str = ""


def _normalize_key(device: str, action: str) -> tuple[str, str]:
    """Normalize device and action strings for consistent lookup."""
    norm_device = device.strip().lower().replace("-", "_").replace(" ", "_")
    norm_action = action.strip().lower().replace("-", "_").replace(" ", "_")
    return norm_device, norm_action


class RiskPolicy:
    """Evaluates the risk level of smart home actions against configured rules.

    Defaults to HIGH risk for any unmapped or unrecognized (device, action)
    combination, strictly adhering to the Fail-Closed security principle.
    """

    DEFAULT_POLICY_PATH = Path(__file__).parent / "policy.yaml"

    def __init__(
        self,
        rules: Mapping[tuple[str, str], RiskLevel] | None = None,
        default_risk: RiskLevel = RiskLevel.HIGH,
    ) -> None:
        self._rules: dict[tuple[str, str], RiskLevel] = dict(rules or {})
        self._default_risk: RiskLevel = default_risk

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> "RiskPolicy":
        """Load policy rules from a YAML file."""
        file_path = Path(path)
        if not file_path.exists():
            # If the specified policy file does not exist, fail closed
            return cls(rules={}, default_risk=RiskLevel.HIGH)

        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return cls.from_dict(data)

    @classmethod
    def from_yaml_string(cls, yaml_content: str) -> "RiskPolicy":
        """Load policy rules from a YAML string."""
        data = yaml.safe_load(yaml_content) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RiskPolicy":
        """Build a RiskPolicy from parsed dictionary data."""
        default_risk_str = str(data.get("default_risk", "HIGH")).upper()
        try:
            default_risk = RiskLevel(default_risk_str)
        except ValueError:
            default_risk = RiskLevel.HIGH

        rules: dict[tuple[str, str], RiskLevel] = {}
        for rule_raw in data.get("rules", []):
            device = rule_raw.get("device")
            action = rule_raw.get("action")
            risk_str = str(rule_raw.get("risk", "HIGH")).upper()
            if not device or not action:
                continue

            try:
                risk = RiskLevel(risk_str)
            except ValueError:
                risk = RiskLevel.HIGH

            key = _normalize_key(str(device), str(action))
            rules[key] = risk

        return cls(rules=rules, default_risk=default_risk)

    @classmethod
    def default(cls) -> "RiskPolicy":
        """Load the bundled default policy.yaml or fall back to fail-closed empty rules."""
        if cls.DEFAULT_POLICY_PATH.exists():
            return cls.from_yaml_file(cls.DEFAULT_POLICY_PATH)
        return cls(rules={}, default_risk=RiskLevel.HIGH)

    def get_risk(
        self,
        device: str,
        action: str,
        params: dict[str, Any] | None = None,
    ) -> RiskLevel:
        """Get the risk level for a device and action pair.

        Args:
            device: Name or identifier of target device.
            action: Action being attempted.
            params: Optional dictionary of action parameters evaluated for dynamic safety caps.

        Returns:
            RiskLevel (LOW, MEDIUM, HIGH). Unrecognized actions return HIGH.
        """
        if not device or not action:
            return RiskLevel.HIGH

        # Dynamic climate safety cap: Extreme temperatures outside [65.0°F, 80.0°F]
        # are elevated from LOW to HIGH risk, requiring two-factor owner approval on the phone UI.
        norm_action = str(action).lower().strip()
        norm_device = str(device).lower().strip()
        if (norm_action in ("set_temperature", "set_temp") or "thermostat" in norm_device) and params:
            temp_val = (
                params.get("temperature")
                if "temperature" in params
                else params.get("target_temperature")
                if "target_temperature" in params
                else params.get("target_temp_f")
                if "target_temp_f" in params
                else params.get("temp")
            )
            if temp_val is not None:
                try:
                    t_float = float(temp_val)
                    if t_float < 65.0 or t_float > 80.0:
                        return RiskLevel.HIGH
                except (ValueError, TypeError):
                    return RiskLevel.HIGH

        key = _normalize_key(device, action)
        return self._rules.get(key, self._default_risk)

    def is_high_risk(self, device: str, action: str, params: dict[str, Any] | None = None) -> bool:
        """Return True if the action is classified as HIGH risk."""
        return self.get_risk(device, action, params=params) == RiskLevel.HIGH

    def requires_confirmation(self, device: str, action: str, params: dict[str, Any] | None = None) -> bool:
        """Return True if the action requires caregiver confirmation (MEDIUM or HIGH)."""
        risk = self.get_risk(device, action, params=params)
        return risk in (RiskLevel.MEDIUM, RiskLevel.HIGH)

    @property
    def rule_count(self) -> int:
        """Return the number of configured rules."""
        return len(self._rules)
