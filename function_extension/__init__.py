from .common import (
    decrease_value,
    increase_value,
    set_value,
)
from .rs_dose import decrease_volume
from .rs_power import apply_socket_schedules, handle_local_temp, is_power
from .rs_run import simulate_pump_temperature, sync_pump_intensity
from . import probe_rules, registry, rs_cloud, rs_control, rs_led

__all__ = [
    "apply_socket_schedules",
    "decrease_value",
    "decrease_volume",
    "handle_local_temp",
    "increase_value",
    "is_power",
    "probe_rules",
    "project_control_dashboard",
    "registry",
    "rs_cloud",
    "rs_control",
    "rs_led",
    "set_value",
    "simulate_pump_temperature",
    "sync_pump_intensity",
]

# Expose the control-dashboard projection modifier at package level so the
# config.json "modifiers" mechanism (getattr(function_extension, name)) finds it.
project_control_dashboard = rs_control.project_control_dashboard
