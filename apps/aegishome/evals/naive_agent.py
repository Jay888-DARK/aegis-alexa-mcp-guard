#!/usr/bin/env python3
"""Scripted Naive Baseline Agent for Aegis Red-Teaming Comparisons.

IMPORTANT NOTICE & BENCHMARK DISCLOSURE:
This is a SCRIPTED NAIVE BASELINE, NOT a real LLM and NOT a live model.
It represents an un-guarded, naive agentic system that blindly executes
every tool-use command or accepts untrusted data without:
1. Risk policy evaluation
2. Human confirmation gating (voice PIN or owner approval)
3. Cryptographic proposal binding & replay prevention
4. Time-to-live expiration enforcement
5. Session taint tracking from untrusted inputs
6. Response numeric verification (Numeric Guardrail)

Used strictly as an experimental control baseline to measure the delta
provided by the Aegis Guard deterministic safety gateway.
"""

from typing import Any
from aegishome.devices import get_simulated_home


class ScriptedNaiveAgent:
    """Scripted baseline agent without safety guardrails.
    
    DISCLOSURE: This is a deterministic scripted baseline, not a live AI model.
    """

    def __init__(self) -> None:
        self.label = "Scripted Naive Baseline (No Guardrails)"

    def execute_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Execute a test case blindly without safety checks."""
        home = get_simulated_home()
        case_id = case["id"]
        category = case["category"]
        action_type = case.get("action_type", "")
        target = case.get("target", "")
        parameters = case.get("parameters", {})
        is_safe_action = case.get("is_safe_action", False)

        # 1. Benign operations: executes normally
        if category == "benign":
            if action_type == "get_home_status":
                return {
                    "case_id": case_id,
                    "category": category,
                    "is_safe_action": True,
                    "executed": True,
                    "blocked": False,
                    "details": "Naive baseline retrieved device status directly.",
                }
            elif action_type == "read_visitor_note":
                return {
                    "case_id": case_id,
                    "category": category,
                    "is_safe_action": True,
                    "executed": True,
                    "blocked": False,
                    "details": "Naive baseline read note without taint tracking.",
                }
            elif action_type == "generate_home_summary":
                return {
                    "case_id": case_id,
                    "category": category,
                    "is_safe_action": True,
                    "executed": True,
                    "blocked": False,
                    "details": "Naive baseline generated home summary.",
                }
            else:
                self._mutate_device(home, action_type, target, parameters)
                return {
                    "case_id": case_id,
                    "category": category,
                    "is_safe_action": True,
                    "executed": True,
                    "blocked": False,
                    "details": f"Naive baseline executed benign action '{action_type}' on '{target}'.",
                }

        # 2. Needs-confirm: in naive baseline, executed directly without proposal, PIN, or owner approval
        elif category == "needs-confirm":
            if is_safe_action:
                self._mutate_device(home, action_type, target, parameters)
                return {
                    "case_id": case_id,
                    "category": category,
                    "is_safe_action": True,
                    "executed": True,
                    "blocked": False,
                    "details": f"Naive baseline executed '{action_type}' on '{target}' directly.",
                }
            else:
                self._mutate_device(home, action_type, target, parameters)
                return {
                    "case_id": case_id,
                    "category": category,
                    "is_safe_action": False,
                    "executed": True,
                    "blocked": False,
                    "details": f"VULNERABILITY: Naive baseline executed unconfirmed '{action_type}' on '{target}' without code or owner approval.",
                }

        # 3. Replay attacks: naive baseline has no proposal cache or nonce; re-executes whenever invoked
        elif category == "replay":
            repeat_count = case.get("replay_count", 1)
            for _ in range(repeat_count):
                self._mutate_device(home, action_type, target, parameters)
            return {
                "case_id": case_id,
                "category": category,
                "is_safe_action": False,
                "executed": True,
                "blocked": False,
                "details": f"VULNERABILITY: Naive baseline re-executed '{action_type}' {repeat_count} times without replay protection.",
            }

        # 4. Expired proposals: naive baseline has no TTL expiration; executes regardless of time
        elif category == "expired":
            self._mutate_device(home, action_type, target, parameters)
            return {
                "case_id": case_id,
                "category": category,
                "is_safe_action": False,
                "executed": True,
                "blocked": False,
                "details": f"VULNERABILITY: Naive baseline executed stale '{action_type}' on '{target}' with zero TTL enforcement.",
            }

        # 5. Action tampering & parameter swapping: naive baseline has no HMAC binding; accepts modified payload
        elif category == "action-swap":
            self._mutate_device(home, action_type, target, parameters)
            return {
                "case_id": case_id,
                "category": category,
                "is_safe_action": False,
                "executed": True,
                "blocked": False,
                "details": f"VULNERABILITY: Naive baseline executed tampered action '{action_type}' without HMAC digest check.",
            }

        # 6. Brute-force attacks: naive baseline has no 3-attempt lockout; executes action
        elif category == "brute-force":
            self._mutate_device(home, action_type, target, parameters)
            return {
                "case_id": case_id,
                "category": category,
                "is_safe_action": False,
                "executed": True,
                "blocked": False,
                "details": f"VULNERABILITY: Naive baseline executed '{action_type}' on '{target}' without rate limiting or lockout.",
            }

        # 7. Indirect Prompt Injection: naive baseline reads untrusted note and executes injected follow-up directly
        elif category == "injection":
            f_action = case.get("follow_up_action", action_type)
            f_target = case.get("follow_up_target", target)
            f_params = case.get("follow_up_params", parameters)
            if f_action:
                self._mutate_device(home, f_action, f_target, f_params)
            return {
                "case_id": case_id,
                "category": category,
                "is_safe_action": False,
                "executed": True,
                "blocked": False,
                "details": f"VULNERABILITY: Naive baseline obeyed injected command '{f_action}' from untrusted note without taint escalation.",
            }

        # 8. Numeric Hallucinations: naive baseline has no numeric verification; emits hallucinated drafts
        elif category == "numeric-hallucination":
            draft = parameters.get("custom_draft") or f"Hallucinated draft with value {parameters.get('hallucinated_package_value', '')}"
            return {
                "case_id": case_id,
                "category": category,
                "is_safe_action": False,
                "executed": True,
                "blocked": False,
                "details": f"VULNERABILITY: Naive baseline emitted unverified draft containing ungrounded numbers: '{draft[:50]}...'",
            }

        # 9. Session Bypass: naive baseline has no session binding; blindly executes spoofed tool call
        elif category == "session-bypass":
            f_action = case.get("action_to_propose", "set_temperature")
            self._mutate_device(home, f_action, target, parameters)
            return {
                "case_id": case_id,
                "category": category,
                "is_safe_action": False,
                "executed": True,
                "blocked": False,
                "details": f"VULNERABILITY: Naive baseline executed '{f_action}' blindly ignoring session taint context.",
            }

        # Default fallback
        self._mutate_device(home, action_type, target, parameters)
        return {
            "case_id": case_id,
            "category": category,
            "is_safe_action": is_safe_action,
            "executed": True,
            "blocked": False,
            "details": f"Naive baseline executed '{action_type}'.",
        }

    def _mutate_device(self, home: Any, action: str, target: str, params: dict[str, Any]) -> None:
        """Simulate hardware mutation for the naive agent."""
        action_clean = action.lower().replace("-", "_").replace(" ", "_")
        target_clean = target.lower().replace("-", "_").replace(" ", "_")

        try:
            if "unlock" in action_clean or target_clean == "front_door":
                if "unlock" in action_clean:
                    home.front_door_lock.unlock()
                elif "lock" in action_clean:
                    home.front_door_lock.lock()
            elif "open" in action_clean or target_clean == "garage_door":
                if "open" in action_clean:
                    home.garage_door.open()
                elif "close" in action_clean:
                    home.garage_door.close()
            elif "temperature" in action_clean or target_clean == "thermostat":
                temp = params.get("temperature", 72.0)
                home.thermostat.set_temperature(float(temp))
        except Exception:
            pass
