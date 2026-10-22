"""Modelo ilustrativo y balance en el bus DC. No acciona hardware.

Las eficiencias y constantes NO representan un módulo comercial validado.
La energía inicial de almacenamiento es cero para no contar energía de origen
desconocido como recuperada. El respaldo mantiene la carga crítica completa.
"""
from dataclasses import dataclass
import math


def finite(value: float, low: float, high: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError(f"{name}: número requerido")
    if not math.isfinite(value) or not low <= value <= high:
        raise ValueError(f"{name}: fuera de [{low}, {high}]")
    return float(value)


def illustrative_teg(hot_c: float, cold_c: float, modules: int = 4) -> dict:
    """Seebeck con carga adaptada; Carnot solo limita, no predice eficiencia.

Th/Tc son temperaturas de las CARAS del módulo, no del aire del pasillo.
Qhot se modela como K*deltaT: es un supuesto, no un modelo térmico acoplado.
"""
    finite(hot_c, -50, 150, "hot_c")
    finite(cold_c, -50, 150, "cold_c")
    if type(modules) is not int or not 1 <= modules <= 1000:
        raise ValueError("modules: entero entre 1 y 1000")
    delta = max(0.0, hot_c - cold_c)
    alpha_v_k, resistance_ohm, conductance_w_k = 0.05, 3.0, 0.3
    voc = alpha_v_k * delta
    p_matched = modules * voc**2 / (4 * resistance_ohm)
    q_hot = modules * conductance_w_k * delta
    carnot = delta / (hot_c + 273.15) if delta else 0.0
    p_gross = min(p_matched, q_hot * carnot)
    # Cold start is hypothetical. Select actual converter using its IV curve.
    p_bus = p_gross * 0.8 if delta >= 5 else 0.0
    return {"label": "DATOS SIMULADOS", "delta_k": delta,
            "q_hot_assumed_w": q_hot, "carnot_upper_bound": carnot,
            "teg_gross_w": p_gross, "harvest_dc_w": p_bus}


@dataclass(frozen=True)
class PowerSample:
    harvest_dc_w: float  # At regulated output, after harvester conversion loss.
    hot_c: float
    cold_c: float
    age_s: float = 0.0
    extra_cooling_w: float = 0.0  # Increment versus same load, no recovery.

    def validate(self):
        finite(self.harvest_dc_w, 0, 10000, "harvest_dc_w")
        finite(self.hot_c, -50, 150, "hot_c")
        finite(self.cold_c, -50, 150, "cold_c")
        finite(self.age_s, 0, 86400, "age_s")
        finite(self.extra_cooling_w, 0, 10000, "extra_cooling_w")


@dataclass
class Balance:
    mode: str
    harvest_accepted_wh: float
    load_wh: float
    recovered_to_load_wh: float
    grid_dc_wh: float
    cooling_wh: float
    stored_wh: float
    curtailed_wh: float
    storage_loss_wh: float
    warning: str | None


class EnergyManager:
    """Supervisor/modelo; el power-path real debe ser autónomo de este software."""
    def __init__(self, capacity_wh=0.1, core_w=3.0, optional_w=0.5):
        self.capacity = finite(capacity_wh, 0.001, 1000, "capacity_wh")
        self.core = finite(core_w, 0.01, 10000, "core_w")
        self.optional = finite(optional_w, 0, 10000, "optional_w")
        self.stored = 0.0
        self.reserve = self.capacity * 0.20
        self.eta_charge = 0.90
        self.eta_discharge = 0.90
        self.max_charge_w = 2.0
        self.max_discharge_w = 5.0
        self.full = False

    def step(self, sample: PowerSample, seconds=1.0) -> Balance:
        sample.validate()
        dt = finite(seconds, 0.001, 3600, "seconds") / 3600
        warning = None
        # LAB limits, not universal industrial safe temperatures.
        if sample.age_s > 5:
            warning = "STALE_POWER_TELEMETRY"
        elif sample.hot_c >= 75 or sample.cold_c >= 50:
            warning = "THERMAL_REVIEW_REQUIRED"
        elif sample.hot_c <= sample.cold_c and sample.harvest_dc_w > 0:
            warning = "INCONSISTENT_TELEMETRY"
        harvest_w = 0.0 if warning else sample.harvest_dc_w
        # Hysteresis: optional analytics run only on sustained surplus + buffer.
        if warning or harvest_w < self.core + self.optional or self.stored < 0.4 * self.capacity:
            self.full = False
        elif harvest_w >= self.core + self.optional + 0.25 and self.stored >= 0.6 * self.capacity:
            self.full = True
        mode = "CORE_ONLY" if not self.full else "CORE_PLUS_REPORTS"
        if warning:
            mode = "BACKUP_TELEMETRY_FAULT"
        demand = (self.core + (self.optional if self.full else 0)) * dt
        harvested = harvest_w * dt
        direct = min(harvested, demand)
        deficit, surplus = demand - direct, harvested - direct
        discharge = min(deficit, max(0, self.stored - self.reserve) * self.eta_discharge,
                        self.max_discharge_w * dt)
        # On untrusted thermal telemetry do not claim storage availability.
        if warning:
            discharge = 0.0
        withdrawn = discharge / self.eta_discharge
        self.stored -= withdrawn
        charge_in = min(surplus, (self.capacity - self.stored) / self.eta_charge,
                        self.max_charge_w * dt)
        self.stored += charge_in * self.eta_charge
        grid = max(0, deficit - discharge)
        loss = withdrawn - discharge + charge_in * (1 - self.eta_charge)
        return Balance(mode, harvested, demand, direct + discharge, grid,
                       sample.extra_cooling_w * dt, self.stored,
                       max(0, surplus - charge_in), loss, warning)


def summarize(balances: list[Balance], kg_co2e_kwh=0.4) -> dict:
    """Electricity accounting only; manufacturing is explicitly excluded."""
    factor = finite(kg_co2e_kwh, 0, 5, "kg_co2e_kwh")
    totals = {key: sum(getattr(b, key) for b in balances) for key in (
        "harvest_accepted_wh", "load_wh", "recovered_to_load_wh", "grid_dc_wh",
        "cooling_wh", "curtailed_wh", "storage_loss_wh")}
    # Same 90% AC/DC assumption on reference and backup. Explicit, not measured.
    backup_efficiency = 0.90
    actual_ac = totals["grid_dc_wh"] / backup_efficiency + totals["cooling_wh"]
    reference_ac = totals["load_wh"] / backup_efficiency
    savings = reference_ac - actual_ac
    totals.update({"stored_final_wh": balances[-1].stored_wh if balances else 0,
                   "backup_ac_efficiency_assumed": backup_efficiency,
                   "grid_increment_vs_no_monitor_wh": actual_ac,
                   "grid_reference_same_load_wh": reference_ac,
                   "grid_saving_vs_same_load_wh": savings,
                   "operational_kg_co2e_saving_estimate": savings / 1000 * factor,
                   "carbon_factor_assumed_kg_kwh": factor,
                   "embodied_carbon_included": False,
                   "recovered_load_fraction": totals["recovered_to_load_wh"] / totals["load_wh"]
                   if totals["load_wh"] else 0})
    return totals
