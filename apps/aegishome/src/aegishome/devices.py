"""Simulated smart home devices for AegisHome caregiver scenario.

Includes:
- front_door_lock (locked / unlocked)
- garage_door (open / closed)
- porch_camera (events with timestamps, dwell time in seconds)
- thermostat (current and target temperature in Fahrenheit, HVAC mode)
- package_sensor (package presence and monetary value in USD)
Persists state in memory with a reset() method for testing and reproducibility.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CameraEvent:
    """Motion or visitor event recorded by the porch camera."""

    timestamp: str
    event_type: str
    dwell_time_seconds: float
    description: str = ""


@dataclass
class FrontDoorLock:
    """Smart lock for the main residence entrance."""

    locked: bool = True

    def lock(self) -> None:
        self.locked = True

    def unlock(self) -> None:
        self.locked = False

    @property
    def status(self) -> str:
        return "locked" if self.locked else "unlocked"


@dataclass
class GarageDoor:
    """Motorized garage door."""

    state: str = "closed"

    def open(self) -> None:
        self.state = "open"

    def close(self) -> None:
        self.state = "closed"

    @property
    def status(self) -> str:
        return self.state


@dataclass
class PorchCamera:
    """Front porch security camera tracking visitor presence and dwell time."""

    events: list[CameraEvent] = field(default_factory=list)

    def add_event(
        self,
        event_type: str,
        dwell_time_seconds: float,
        description: str = "",
        timestamp: str | None = None,
    ) -> CameraEvent:
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        event = CameraEvent(
            timestamp=timestamp,
            event_type=event_type,
            dwell_time_seconds=float(dwell_time_seconds),
            description=description,
        )
        self.events.append(event)
        return event

    def clear_events(self) -> None:
        self.events.clear()

    @property
    def latest_event(self) -> CameraEvent | None:
        return self.events[-1] if self.events else None


@dataclass
class Thermostat:
    """Smart climate control unit."""

    temperature: float = 71.0
    target_temperature: float = 71.0
    hvac_mode: str = "heat"

    def set_temperature(self, temp_f: float) -> None:
        self.target_temperature = float(temp_f)

    def set_mode(self, mode: str) -> None:
        self.hvac_mode = mode


@dataclass
class PackageSensor:
    """Porch weight/optical package detector tracking package presence and USD value."""

    package_present: bool = True
    package_value_usd: float = 120.0
    package_description: str = "Prescription Medication Delivery"

    def detect_package(self, value_usd: float, description: str = "") -> None:
        self.package_present = True
        self.package_value_usd = float(value_usd)
        self.package_description = description

    def clear(self) -> None:
        self.package_present = False
        self.package_value_usd = 0.0
        self.package_description = ""


class SimulatedHome:
    """In-memory stateful container representing the caregiver smart-home environment."""

    def __init__(self) -> None:
        self.front_door_lock = FrontDoorLock()
        self.garage_door = GarageDoor()
        self.porch_camera = PorchCamera()
        self.thermostat = Thermostat()
        self.package_sensor = PackageSensor()
        self.resident = {
            "name": "Eleanor Vance",
            "state": "resting_in_bedroom",
            "heart_rate_bpm": 72,
        }
        self.reset()

    def reset(self) -> None:
        """Reset all devices to their initial baseline states."""
        self.front_door_lock.locked = True
        self.garage_door.state = "closed"
        self.thermostat.temperature = 71.0
        self.thermostat.target_temperature = 71.0
        self.thermostat.hvac_mode = "heat"
        self.package_sensor.package_present = True
        self.package_sensor.package_value_usd = 120.0
        self.package_sensor.package_description = "Prescription Medication Delivery"
        self.porch_camera.events = [
            CameraEvent(
                timestamp="2026-10-20T14:28:15Z",
                event_type="person_at_door",
                dwell_time_seconds=42.5,
                description="Delivery courier dropped package at porch",
            )
        ]
        self.resident = {
            "name": "Eleanor Vance",
            "state": "resting_in_bedroom",
            "heart_rate_bpm": 72,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete simulated home state into a JSON-compatible dictionary."""
        return {
            "resident": dict(self.resident),
            "front_door_lock": {
                "locked": self.front_door_lock.locked,
                "status": self.front_door_lock.status,
            },
            "doors": {
                "front_door": self.front_door_lock.status,
                "garage_door": self.garage_door.state,
            },
            "garage_door": {
                "state": self.garage_door.state,
            },
            "porch_camera": {
                "event_count": len(self.porch_camera.events),
                "latest_event": (
                    {
                        "timestamp": self.porch_camera.latest_event.timestamp,
                        "event_type": self.porch_camera.latest_event.event_type,
                        "dwell_time_seconds": self.porch_camera.latest_event.dwell_time_seconds,
                        "description": self.porch_camera.latest_event.description,
                    }
                    if self.porch_camera.latest_event
                    else None
                ),
                "events": [
                    {
                        "timestamp": e.timestamp,
                        "event_type": e.event_type,
                        "dwell_time_seconds": e.dwell_time_seconds,
                        "description": e.description,
                    }
                    for e in self.porch_camera.events
                ],
            },
            "thermostat": {
                "temperature": self.thermostat.temperature,
                "current_temperature_f": self.thermostat.temperature,
                "target_temperature": self.thermostat.target_temperature,
                "target_temp_f": self.thermostat.target_temperature,
                "hvac_mode": self.thermostat.hvac_mode,
            },
            "climate": {
                "current_temp_f": self.thermostat.temperature,
                "target_temp_f": self.thermostat.target_temperature,
                "hvac_mode": self.thermostat.hvac_mode,
            },
            "package_sensor": {
                "package_present": self.package_sensor.package_present,
                "package_value_usd": self.package_sensor.package_value_usd,
                "package_description": self.package_sensor.package_description,
            },
        }


# Global in-memory singleton
_GLOBAL_HOME = SimulatedHome()


def get_simulated_home() -> SimulatedHome:
    """Retrieve the global in-memory SimulatedHome instance."""
    return _GLOBAL_HOME


def reset() -> None:
    """Reset the global SimulatedHome instance to its baseline state."""
    _GLOBAL_HOME.reset()
