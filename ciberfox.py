# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ciberfox contributors
"""Ciberfox en un solo archivo: laboratorio offline de monitoreo OT y recuperación térmica.

Uso:
  python3 ciberfox.py demo --out nueva_demo
  python3 ciberfox.py test
  python3 ciberfox.py analyze-pcap --pcap ... --tshark ... --approved-sha256 ... [--policy p.json --policy-sha256 H]
                      [--audit-log bitacora.jsonl] [--sandbox require|best-effort] [--timeout S]
  python3 ciberfox.py replay-power --csv ... [--policy p.json] | audit-verify --log bitacora.jsonl
"""
from dataclasses import dataclass, asdict
from ipaddress import IPv4Address
from pathlib import Path
import argparse
import csv
import base64
import getpass
import hashlib
import html
import json
import time
import math
import os
import random
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest


# ======================================================================
# PAQUETE
# ======================================================================
"""Ciberfox: laboratorio offline de monitoreo OT y recuperación térmica."""


# ======================================================================
# ciberfox/energy.py
# ======================================================================
"""Modelo ilustrativo y balance en el bus DC. No acciona hardware.

Las eficiencias y constantes NO representan un módulo comercial validado.
La energía inicial de almacenamiento es cero para no contar energía de origen
desconocido como recuperada. El respaldo mantiene la carga crítica completa.
"""


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
    def __init__(self, capacity_wh=0.1, core_w=3.0, optional_w=0.5, hot_limit_c=75.0, cold_limit_c=50.0, stale_s=5.0):
        self.capacity = finite(capacity_wh, 0.001, 1000, "capacity_wh")
        self.core = finite(core_w, 0.01, 10000, "core_w")
        self.optional = finite(optional_w, 0, 10000, "optional_w")
        self.hot_limit = finite(hot_limit_c, -50, 150, "hot_limit_c")
        self.cold_limit = finite(cold_limit_c, -50, 150, "cold_limit_c")
        self.stale_s = finite(stale_s, 0.1, 86400, "stale_s")
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
        if sample.age_s > self.stale_s:
            warning = "STALE_POWER_TELEMETRY"
        elif sample.hot_c >= self.hot_limit or sample.cold_c >= self.cold_limit:
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


def summarize(balances: list[Balance], kg_co2e_kwh=0.4, backup_efficiency=0.90) -> dict:
    """Electricity accounting only; manufacturing is explicitly excluded."""
    factor = finite(kg_co2e_kwh, 0, 5, "kg_co2e_kwh")
    totals = {key: sum(getattr(b, key) for b in balances) for key in (
        "harvest_accepted_wh", "load_wh", "recovered_to_load_wh", "grid_dc_wh",
        "cooling_wh", "curtailed_wh", "storage_loss_wh")}
    # Same 90% AC/DC assumption on reference and backup. Explicit, not measured.
    backup_efficiency = finite(backup_efficiency, 0.01, 1, "backup_efficiency")
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


# ======================================================================
# ciberfox/detector.py
# ======================================================================
"""Reglas de laboratorio, sin conexiones ni comandos a PLCs."""
POLICY_KEYS = {"allowed_sources", "allowed_readers", "targets", "registers", "coils", "energy"}
ENERGY_MANAGER_KEYS = {"capacity_wh", "core_w", "optional_w", "hot_limit_c", "cold_limit_c", "stale_s"}
ENERGY_SUMMARY_KEYS = {"kg_co2e_kwh", "backup_efficiency"}


@dataclass(frozen=True)
class Event:
    timestamp: float
    source: str
    destination: str
    unit: int
    function: int
    address: int | None = None
    value: int | None = None
    quantity: int | None = None
    values: tuple | None = None
    src_port: int | None = None  # evidencia de flujo; NO autentica la identidad del origen
    flow_id: int | None = None   # tcp.stream de TShark: agrupa la conversación (5-tupla) completa
    transaction_id: int | None = None  # mbtcp.trans_id: correlaciona solicitud/respuesta

    def validate(self):
        finite(self.timestamp, 0, 1e12, "timestamp")
        IPv4Address(self.source)
        IPv4Address(self.destination)
        for name, limit in (("unit", 255), ("function", 255)):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= limit:
                raise ValueError(name)
        if self.flow_id is not None and (type(self.flow_id) is not int or not 0 <= self.flow_id <= 2**32):
            raise ValueError("flow_id")
        for name in ("address", "value", "quantity", "src_port", "transaction_id"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or not 0 <= value <= 65535):
                raise ValueError(name)
        if self.values is not None and (type(self.values) is not tuple or len(self.values) > 2000 or
                                        any(type(v) is not int or not 0 <= v <= 65535 for v in self.values)):
            raise ValueError("values")
        if self.function == 6 and (self.address is None or self.value is None):
            raise ValueError("FC06 necesita dirección y valor")


@dataclass(frozen=True)
class Policy:
    """Política por despliegue (H3/H4). Los valores por defecto son SOLO de laboratorio."""
    allowed_sources: frozenset
    allowed_readers: frozenset
    targets: frozenset
    registers: dict
    coils: dict
    energy_manager: dict
    energy_summary: dict
    sha256: str = "default-laboratorio"


def default_policy() -> Policy:
    return Policy(frozenset({"192.0.2.10"}), frozenset({"192.0.2.10"}),
                  frozenset({("192.0.2.20", 1)}), {100: (20, 60, "consigna_bomba_demo")}, {}, {}, {})


def _int(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"Política {name}: entero en [{low}, {high}]")
    return value


def _ip(value, name):
    if type(value) is not str:
        raise ValueError(f"Política {name}: IPv4 como texto")
    IPv4Address(value)
    return value


def _label(value, name):
    if type(value) is not str or not 1 <= len(value) <= 64 or not value.isprintable():
        raise ValueError(f"Política {name}: texto imprimible de 1 a 64 caracteres")
    return value


def _ip_list(value, name):
    if type(value) is not list or not 1 <= len(value) <= 256:
        raise ValueError(f"Política {name}: lista de 1 a 256 IPv4")
    return frozenset(_ip(item, name) for item in value)


def load_policy(path: Path, expected_sha256: str | None = None) -> Policy:
    """Carga estricta: archivo regular pequeño, hash opcional fijado, claves y rangos validados."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise ValueError("Política: archivo regular <=64 KiB, sin enlace simbólico")
    data = path.read_bytes()
    if len(data) > 64 * 1024:
        raise ValueError("Política: archivo demasiado grande")
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and (not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or expected_sha256 != digest):
        raise ValueError("Política: SHA256 distinto del aprobado")

    def reject(constant):
        raise ValueError("Política: constante JSON no válida")

    raw = json.loads(data.decode("utf-8"), parse_constant=reject)
    if type(raw) is not dict or set(raw) - POLICY_KEYS:
        raise ValueError("Política: formato inválido o claves desconocidas")
    for required in ("allowed_sources", "targets", "registers"):
        if required not in raw:
            raise ValueError(f"Política: falta {required}")
    sources = _ip_list(raw["allowed_sources"], "allowed_sources")
    readers = _ip_list(raw["allowed_readers"], "allowed_readers") if "allowed_readers" in raw else sources
    targets = raw["targets"]
    if type(targets) is not list or not 1 <= len(targets) <= 256:
        raise ValueError("Política targets: lista de 1 a 256 pares [ip, unidad]")
    parsed_targets = set()
    for item in targets:
        if type(item) is not list or len(item) != 2:
            raise ValueError("Política targets: cada elemento es [ip, unidad]")
        parsed_targets.add((_ip(item[0], "targets"), _int(item[1], 0, 255, "targets.unit")))

    def address(key, name):
        if type(key) is not str or not key.isdigit() or len(key) > 5:
            raise ValueError(f"Política {name}: dirección numérica")
        return _int(int(key), 0, 65535, name)

    registers = {}
    if type(raw["registers"]) is not dict or len(raw["registers"]) > 4096:
        raise ValueError("Política registers: objeto dirección -> [mín, máx, nombre]")
    for key, item in raw["registers"].items():
        if type(item) is not list or len(item) != 3:
            raise ValueError("Política registers: [mín, máx, nombre]")
        low, high = _int(item[0], 0, 65535, "registers.min"), _int(item[1], 0, 65535, "registers.max")
        if low > high:
            raise ValueError("Política registers: mín > máx")
        registers[address(key, "registers")] = (low, high, _label(item[2], "registers.nombre"))
    coils = {}
    raw_coils = raw.get("coils", {})
    if type(raw_coils) is not dict or len(raw_coils) > 4096:
        raise ValueError("Política coils: objeto dirección -> [[valores], nombre]")
    for key, item in raw_coils.items():
        if type(item) is not list or len(item) != 2 or type(item[0]) is not list or not item[0]:
            raise ValueError("Política coils: [[valores permitidos], nombre]")
        values = frozenset(_int(v, 0, 1, "coils.valor") for v in item[0])
        coils[address(key, "coils")] = (values, _label(item[1], "coils.nombre"))
    energy = raw.get("energy", {})
    if type(energy) is not dict or set(energy) - (ENERGY_MANAGER_KEYS | ENERGY_SUMMARY_KEYS):
        raise ValueError("Política energy: claves desconocidas")
    manager_cfg = {k: energy[k] for k in ENERGY_MANAGER_KEYS if k in energy}
    summary_cfg = {k: energy[k] for k in ENERGY_SUMMARY_KEYS if k in energy}
    EnergyManager(**manager_cfg)  # valida rangos
    if "kg_co2e_kwh" in summary_cfg:
        finite(summary_cfg["kg_co2e_kwh"], 0, 5, "kg_co2e_kwh")
    if "backup_efficiency" in summary_cfg:
        finite(summary_cfg["backup_efficiency"], 0.01, 1, "backup_efficiency")
    return Policy(sources, readers, frozenset(parsed_targets), registers, coils,
                  manager_cfg, summary_cfg, digest)


def _sample(items):
    return ", ".join(str(x) for x in items[:5]) + (f" … ({len(items)} en total)" if len(items) > 5 else "")


class Detector:
    """Allowlist por política. Valores crudos sin signo; los valores por defecto NO son configuración de una planta."""
    MAX_REGISTERS = 123   # límite de la especificación Modbus para FC16
    MAX_COILS = 1968      # límite de la especificación Modbus para FC15
    READ_WINDOW_S = 60.0  # agregación de UNAUTHORIZED_READ
    READ_FLOOD_COUNT = 100  # lecturas no autorizadas por ventana que escalan a READ_FLOOD (umbral de laboratorio)

    def uninspected(self, evidence: dict) -> dict:
        """Fila que el adaptador no pudo separar/interpretar (p. ej. varias ADU en un segmento TCP).
        Antes solo sumaba a rejected_rows; un atacante podía esconder una escritura detrás de una lectura."""
        self.count += 1
        functions = evidence.get("functions", [])
        writes = sorted(set(functions) & WRITE_FUNCTIONS)
        unknown = not functions
        code = "UNINSPECTED_CONTROL" if writes or unknown else "UNINSPECTED_REQUEST"
        detail = (f"incluye escritura FC{', FC'.join(map(str, writes))}" if writes
                  else "funciones no identificables" if unknown else "solo lecturas")
        authorized = evidence.get("source") in self.allowed
        return {"code": code,
                "reason": f"Solicitud no inspeccionable ({evidence.get('adus_in_row', '?')} ADU en una fila; {detail}); "
                          f"origen {'autorizado' if authorized else 'NO autorizado'} para comandos",
                "event": {**evidence, "source_authorized_for_writes": authorized},
                "action": "REVISIÓN HUMANA; sin bloqueo automático"}

    def __init__(self, policy: Policy | None = None):
        policy = policy or default_policy()
        self.allowed = set(policy.allowed_sources)
        self.readers = set(policy.allowed_readers)
        self.targets = set(policy.targets)
        self.registers = dict(policy.registers)
        self.coils = dict(policy.coils)
        self.count = 0
        self._read_alerts = {}  # (origen, destino, unidad) -> alerta abierta de lectura no autorizada

    def inspect(self, event: Event) -> list[dict]:
        event.validate()
        self.count += 1
        alerts = []

        def alert(code, reason):
            alerts.append({"code": code, "reason": reason, "event": asdict(event),
                           "action": "REVISIÓN HUMANA; sin bloqueo automático"})

        if (event.destination, event.unit) not in self.targets:
            alert("UNEXPECTED_ASSET", "Destino o unidad fuera de la política de laboratorio")
        # Read-only Modbus functions have no write semantics validated here.
        if event.function in (1, 2, 3, 4):
            if event.source not in self.readers:
                # Agregada: 2000 lecturas de una inundación no deben producir 2000 alertas que oculten
                # las importantes (fatiga del operador). Una alerta por flujo lógico y ventana.
                key = (event.source, event.destination, event.unit)
                open_alert = self._read_alerts.get(key)
                if open_alert and event.timestamp - open_alert["first_timestamp"] <= self.READ_WINDOW_S:
                    open_alert["occurrences"] += 1
                    open_alert["last_timestamp"] = event.timestamp
                    open_alert["functions"] = sorted(set(open_alert["functions"]) | {event.function})
                    if open_alert["occurrences"] == self.READ_FLOOD_COUNT:  # escalamiento único por ventana
                        alert("READ_FLOOD", f"{self.READ_FLOOD_COUNT} lecturas no autorizadas en "
                                            f"{event.timestamp - open_alert['first_timestamp']:.1f} s: posible inundación")
                else:
                    alert("UNAUTHORIZED_READ", "Lectura desde origen no autorizado (posible reconocimiento o "
                                               f"inundación); repeticiones agregadas en {self.READ_WINDOW_S:g} s")
                    alerts[-1].update({"occurrences": 1, "first_timestamp": event.timestamp,
                                       "last_timestamp": event.timestamp, "functions": [event.function]})
                    self._read_alerts[key] = alerts[-1]
            return alerts
        if event.source not in self.allowed:
            alert("UNAUTHORIZED_COMMAND", "Origen no autorizado para comandos de control")
        if event.function in (5, 15, 16):
            self._write_multi(event, alert)
            return alerts
        if event.function != 6:
            alert("UNSUPPORTED_CONTROL", "Función no cubierta: requiere revisión; no se declara segura")
            return alerts
        if event.address not in self.registers:
            alert("UNAPPROVED_REGISTER", "Escritura fuera del mapa de registros permitido")
        else:
            low, high, name = self.registers[event.address]
            if not low <= event.value <= high:
                alert("PROCESS_LIMIT", f"{name}: valor fuera del intervalo de laboratorio [{low}, {high}]")
        return alerts

    def _write_multi(self, event, alert):
        incomplete = ("UNSUPPORTED_CONTROL", "Campos incompletos en función de escritura: requiere revisión; no se declara segura")
        if event.function == 5:
            if event.address is None or event.value is None:
                return alert(*incomplete)
            if event.value not in (0, 1):
                return alert("MALFORMED_WRITE", f"FC05 con valor 0x{event.value:04x}: la especificación solo admite FF00/0000")
            entry = self.coils.get(event.address)
            if entry is None:
                alert("UNAPPROVED_COIL", "Escritura de bobina fuera del mapa permitido")
            elif event.value not in entry[0]:
                alert("PROCESS_LIMIT", f"{entry[1]}: estado de bobina {event.value} no permitido")
            return
        if event.address is None or event.quantity is None or (event.function == 16 and event.values is None):
            return alert(*incomplete)
        limit = self.MAX_REGISTERS if event.function == 16 else self.MAX_COILS
        if (not 1 <= event.quantity <= limit or event.address + event.quantity > 65536 or
                (event.function == 16 and len(event.values) != event.quantity)):
            return alert("MALFORMED_WRITE", "Cantidad/direcciones/valores inconsistentes con la especificación Modbus")
        addresses = list(range(event.address, event.address + event.quantity))
        if event.function == 15:
            bad = [a for a in addresses if a not in self.coils]
            if bad:
                alert("UNAPPROVED_COIL", f"Bobinas fuera del mapa permitido: {_sample(bad)}")
            if event.values is None:
                return alert("UNSUPPORTED_CONTROL", "FC15 sin estados de bobina extraídos: bits no validados")
            if len(event.values) != event.quantity:
                return alert("MALFORMED_WRITE", "FC15: número de bits distinto de la cantidad declarada")
            over = [f"{a}={v}" for a, v in zip(addresses, event.values)
                    if a in self.coils and v not in self.coils[a][0]]
            if over:
                alert("PROCESS_LIMIT", f"Estados de bobina no permitidos: {_sample(over)}")
            return
        bad = [a for a in addresses if a not in self.registers]
        if bad:
            alert("UNAPPROVED_REGISTER", f"Registros fuera del mapa permitido: {_sample(bad)}")
        over = [f"{a}={v}" for a, v in zip(addresses, event.values)
                if a in self.registers and not self.registers[a][0] <= v <= self.registers[a][1]]
        if over:
            alert("PROCESS_LIMIT", f"Valores fuera del intervalo permitido: {_sample(over)}")


# ======================================================================
# ciberfox/limited_exec.py
# ======================================================================
"""Lanzador POSIX endurecido (H1).

Linux (probado con TShark 4.6.9 real, kernel 6.18, usuario sin root), en este orden:
  1. límites de recursos (incl. RLIMIT_AS)
  2. no_new_privs
  3. namespaces de usuario + red sin privilegios: el proceso no tiene ninguna interfaz de red
  4. Landlock: solo lectura/ejecución en directorios del sistema y del binario; escritura SOLO en
     el directorio temporal del análisis. El resto del disco (p. ej. $HOME, ~/.ssh) es inaccesible
  5. seccomp: deniega sockets, ptrace, process_vm_* e io_uring, y la ABI x32 (evita evasión)
  6. hash del binario verificado sobre el MISMO descriptor que se ejecuta (fexecve): sin ventana TOCTOU
macOS: límites + sandbox-exec (SIN PROBAR). Sigue sin ser un contenedor/VM."""
SANDBOX_EXIT = 97
HASH_EXIT = 98
# (AUDIT_ARCH, syscalls denegadas): sockets, ptrace, process_vm_readv/writev, io_uring_setup/enter/register
DENY_SYSCALLS = {"x86_64": (0xC000003E, (41, 42, 43, 44, 45, 46, 47, 49, 50, 53, 101, 288, 299, 307,
                                         310, 311, 425, 426, 427)),
                 "aarch64": (0xC00000B7, (198, 199, 200, 201, 202, 203, 206, 207, 211, 212, 117, 242, 243, 269,
                                          270, 271, 425, 426, 427))}
X32_SYSCALL_BIT = 0x40000000
MACOS_PROFILE = "(version 1)(allow default)(deny network*)"
SYSTEM_READ_DIRS = ("/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc", "/proc", "/sys/devices/system/cpu")
LANDLOCK_SYSCALLS = {"x86_64": (444, 445, 446), "aarch64": (444, 445, 446)}


def _limit(name, value):
    import resource
    try:
        resource.setrlimit(getattr(resource, name), (value, value))
        return True
    except (ValueError, OSError, AttributeError):
        return False


def _libc():
    import ctypes
    return ctypes.CDLL(None, use_errno=True)


def _no_new_privs():
    return _libc().prctl(38, 1, 0, 0, 0) == 0  # PR_SET_NO_NEW_PRIVS


def _linux_namespaces():
    """Usuario + red sin privilegios. Conserva el mismo uid/gid visible (mapa 1:1)."""
    uid, gid = os.getuid(), os.getgid()
    try:
        os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
        for name, content in (("setgroups", "deny"), ("uid_map", f"{uid} {uid} 1"), ("gid_map", f"{gid} {gid} 1")):
            with open(f"/proc/self/{name}", "w") as stream:
                stream.write(content)
        return True
    except (OSError, AttributeError):
        return False


def _linux_landlock(binary: str | None, workdir: str):
    """Landlock: lectura/ejecución en el sistema y el binario; escritura SOLO en workdir. Devuelve ABI o 0."""
    import ctypes
    import platform
    if platform.machine() not in LANDLOCK_SYSCALLS:
        return 0
    create, add_rule, restrict = LANDLOCK_SYSCALLS[platform.machine()]
    libc = _libc()
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(create, None, ctypes.c_size_t(0), ctypes.c_uint32(1))  # LANDLOCK_CREATE_RULESET_VERSION
    if abi < 1:
        return 0
    bits = 13 if abi == 1 else 14 if abi == 2 else 15 if abi < 5 else 16
    handled = (1 << bits) - 1
    read_exec = 0b1101  # EXECUTE | READ_FILE | READ_DIR
    file_rights = 0b0111 | ((1 << 14) if bits > 14 else 0)  # EXECUTE | WRITE | READ (+TRUNCATE)

    class RulesetAttr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    class PathBeneath(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

    attr = RulesetAttr(handled)
    ruleset = libc.syscall(create, ctypes.byref(attr), ctypes.c_size_t(ctypes.sizeof(attr)), ctypes.c_uint32(0))
    if ruleset < 0:
        return 0
    try:
        rules = [(path, read_exec) for path in SYSTEM_READ_DIRS]
        if binary:
            folder = os.path.dirname(binary)
            prefix = os.path.dirname(folder)
            rules.append((folder, read_exec))
            rules += [(os.path.join(prefix, sub), read_exec) for sub in ("lib", "lib64", "share", "libexec")]
        rules += [("/dev/null", file_rights & ~1), ("/dev/urandom", 0b0100), (workdir, handled)]
        for path, access in rules:
            try:
                fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except OSError:
                continue
            try:
                if not os.path.isdir(path):
                    access &= file_rights
                rule = PathBeneath(access & handled, fd)
                if libc.syscall(add_rule, ctypes.c_int(ruleset), ctypes.c_int(1), ctypes.byref(rule), ctypes.c_uint32(0)) != 0:
                    return 0
            finally:
                os.close(fd)
        if libc.syscall(restrict, ctypes.c_int(ruleset), ctypes.c_uint32(0)) != 0:
            return 0
        return abi
    finally:
        os.close(ruleset)


def _linux_seccomp():
    """Filtro de denegación. La ABI x32 se deniega completa (si no, socket() vía x32 evade la lista)."""
    import ctypes
    import platform
    if platform.machine() not in DENY_SYSCALLS:
        return False
    audit_arch, numbers = DENY_SYSCALLS[platform.machine()]

    class SockFilter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]

    count = len(numbers)
    # LD arch; JEQ arch → sigue / KILL; LD nr; [x86_64] JGE x32 → ERRNO; JEQ nr_i → ERRNO; ALLOW; ERRNO
    program = [(0x20, 0, 0, 4), (0x15, 1, 0, audit_arch), (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    if platform.machine() == "x86_64":
        program.append((0x35, count + 1, 0, X32_SYSCALL_BIT))  # JGE: salta directo a ERRNO
    program += [(0x15, count - index, 0, number) for index, number in enumerate(numbers)]
    program += [(0x06, 0, 0, 0x7FFF0000), (0x06, 0, 0, 0x00050001)]  # ALLOW / ERRNO(EPERM)
    array = (SockFilter * len(program))(*[SockFilter(*item) for item in program])
    fprog = SockFprog(len(program), array)
    return _libc().prctl(22, 2, ctypes.byref(fprog), 0, 0) == 0  # PR_SET_SECCOMP, FILTER


def apply_sandbox(binary: str | None = None, macos_sandbox: bool = True):
    layers = {"rlimit_core": _limit("RLIMIT_CORE", 0), "rlimit_cpu": _limit("RLIMIT_CPU", 20),
              "rlimit_fsize": _limit("RLIMIT_FSIZE", 32 * 1024**2), "rlimit_nofile": _limit("RLIMIT_NOFILE", 64),
              "rlimit_as": _limit("RLIMIT_AS", 512 * 1024**2),
              "rlimit_as_enforced_by_os": sys.platform.startswith("linux")}
    if sys.platform.startswith("linux"):
        layers["no_new_privs"] = _no_new_privs()
        layers["user_net_namespaces"] = _linux_namespaces()
        abi = _linux_landlock(binary, os.getcwd()) if layers["no_new_privs"] else 0
        layers["landlock_filesystem_abi"] = abi
        layers["filesystem_isolation"] = abi > 0
        layers["seccomp_network_deny"] = layers["no_new_privs"] and _linux_seccomp()
    elif sys.platform == "darwin":
        layers["macos_sandbox_exec"] = macos_sandbox and os.access("/usr/bin/sandbox-exec", os.X_OK)
    return layers


def critical_ok(layers):
    """Capas obligatorias en modo require. Los namespaces se reportan pero no se exigen: algunas distros
    (p. ej. Ubuntu con AppArmor restrictivo) los bloquean, y seccomp ya impide crear sockets."""
    need = ["rlimit_core", "rlimit_cpu", "rlimit_fsize", "rlimit_nofile"]
    if sys.platform.startswith("linux"):
        need += ["rlimit_as", "no_new_privs", "seccomp_network_deny", "filesystem_isolation"]
    elif sys.platform == "darwin":
        need += ["macos_sandbox_exec"]
    else:
        return False
    return all(layers.get(key) for key in need)


def limited_exec_main():
    args = sys.argv[2:]
    require = probe = False
    macos_sandbox = True
    expected = None
    while args and args[0].startswith("--"):
        flag = args.pop(0)
        if flag == "--require":
            require = True
        elif flag == "--best-effort":
            # sandbox-exec puede existir pero estar bloqueado por el entorno anfitrión.
            # Este modo conserva los límites POSIX sin prometer aislamiento completo.
            macos_sandbox = False
        elif flag == "--probe":
            probe = True
        elif flag == "--sha256":
            expected = args.pop(0) if args else ""
        else:
            raise SystemExit("Opción desconocida")
    command = args
    if not probe and (not command or not os.path.isabs(command[0])):
        raise SystemExit("Ejecutable absoluto requerido")
    exec_fd = None
    if command:
        # M3: se abre UNA vez sin seguir enlaces; ese mismo descriptor se hashea y se ejecuta (fexecve).
        exec_fd = os.open(command[0], os.O_RDONLY | os.O_NOFOLLOW)
        if expected is not None:
            digest, offset = hashlib.sha256(), 0
            while chunk := os.pread(exec_fd, 1 << 20, offset):
                digest.update(chunk)
                offset += len(chunk)
            if digest.hexdigest() != expected:
                print("Hash del binario distinto al aprobado", file=sys.stderr)
                raise SystemExit(HASH_EXIT)
    layers = apply_sandbox(os.path.realpath(command[0]) if command else None, macos_sandbox=macos_sandbox)
    if require and not critical_ok(layers):
        print("Sandbox requerido no disponible", file=sys.stderr)
        raise SystemExit(SANDBOX_EXIT)
    if probe:
        print(json.dumps(layers))
        raise SystemExit(0)
    if sys.platform == "darwin" and layers.get("macos_sandbox_exec"):
        os.close(exec_fd)
        command = ["/usr/bin/sandbox-exec", "-p", MACOS_PROFILE, *command]
        os.execve(command[0], command, dict(os.environ))
    if os.execve in os.supports_fd:
        os.set_inheritable(exec_fd, True)  # necesario si el ejecutable es un script con #!
        os.execve(exec_fd, command, dict(os.environ))
    os.close(exec_fd)
    os.execve(command[0], command, dict(os.environ))


# ======================================================================
# ciberfox/tshark_adapter.py
# ======================================================================
"""Adaptador OFFLINE. No copia código Wireshark ni usa sus APIs internas.

Solo PCAP clásico Ethernet IPv4, solicitudes Modbus/TCP puerto 502.
La cobertura intencionadamente limitada se devuelve como dato, no se oculta.
"""

FIELDS = ("frame.time_epoch", "ip.src", "ip.dst", "mbtcp.unit_id",
          "modbus.func_code", "modbus.reference_num", "modbus.regval_uint16",
          "modbus.bitval", "modbus.word_cnt", "modbus.bit_cnt", "tcp.srcport",
          "modbus.data", "tcp.stream", "mbtcp.trans_id")
# Verificado con TShark 4.6.9 real: FC15 imprime modbus.bitval como "True,False,..." y FC05 NO usa
# modbus.bitval: su valor sale en modbus.data como "ff00" (ON) o "0000" (OFF).
BOOLEANS = {"1": 1, "0": 0, "True": 1, "False": 0, "true": 1, "false": 0}
FC05_DATA = {"ff00": 1, "0000": 0}
WRITE_FUNCTIONS = frozenset({5, 6, 15, 16, 22, 23})
LIST_FIELDS = {"modbus.regval_uint16": "16", "modbus.bitval": "15"}  # único campo que puede traer lista
PROTOCOLS = "frame,eth,ethertype,vlan,ip,tcp,mbtcp,modbus"
MAX_PCAP_BYTES = 16 * 1024**2
MAX_RECORDS = 50000


def validate_pcap(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_PCAP_BYTES:
        raise ValueError("PCAP: archivo regular <=16 MiB, sin enlace simbólico")
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise ValueError("Solo PCAP clásico de microsegundos; pcapng no admitido en MVP")
        endian = "<" if header[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        major, minor, _, _, snaplen, network = struct.unpack(endian + "HHiIII", header[4:])
        if (major, minor) != (2, 4) or network != 1 or not 1 <= snaplen <= 65535:
            raise ValueError("Se requiere PCAP 2.4 Ethernet, snaplen <=65535")
        count = 0
        while record := stream.read(16):
            if len(record) != 16:
                raise ValueError("Cabecera de paquete truncada")
            _, usec, included, original = struct.unpack(endian + "IIII", record)
            if usec >= 1000000 or not 0 < included <= min(original, snaplen):
                raise ValueError("Longitud/timestamp PCAP inválidos")
            if len(stream.read(included)) != included:
                raise ValueError("Paquete truncado")
            count += 1
            if count > MAX_RECORDS:
                raise ValueError("Límite de paquetes excedido")
        if not count:
            raise ValueError("PCAP sin paquetes")
    return count


def check_version(text: str):
    match = re.match(r"TShark \(Wireshark\) (\d+)\.(\d+)\.(\d+)(\S*)(?:\s|$)", text)
    if not match:
        raise ValueError("No se pudo verificar versión de TShark")
    major, minor, patch = map(int, match.groups()[:3])
    suffix = match.group(4)
    if (major, minor) != (4, 6) or patch < 9 or suffix:
        raise ValueError("Política revisada 2026-10-22: rama estable 4.6, parche >=9; revisar antes de ampliar")
    return f"{major}.{minor}.{patch}{suffix}"


def parse_row(line: str) -> Event:
    values = line.rstrip("\r\n").split("\t")
    if len(values) != len(FIELDS):
        raise ValueError("Fila ambigua/múltiples PDU: no se descartan valores silenciosamente")
    (timestamp, source, destination, unit, function, address, regval, bitval, word_cnt, bit_cnt,
     src_port, data, stream, trans_id) = values
    for name, value in zip(FIELDS, values):
        # Solo los valores de FC16 (registros) o FC15 (bits) pueden traer lista; otra coma = varias ADU.
        if "," in value and LIST_FIELDS.get(name) != function:
            raise ValueError("Fila ambigua/múltiples PDU: no se descartan valores silenciosamente")
    code = int(function)
    quantity = values_tuple = None
    value = int(regval) if regval and code != 16 else None
    if code == 16:
        values_tuple = tuple(int(item) for item in regval.split(",")) if regval else None
        quantity = int(word_cnt) if word_cnt else None
    elif code == 15:
        quantity = int(bit_cnt) if bit_cnt else None
        if bitval:
            if any(item not in BOOLEANS for item in bitval.split(",")):
                raise ValueError("FC15 con bits no interpretables")
            values_tuple = tuple(BOOLEANS[item] for item in bitval.split(","))
    elif code == 5:
        if data.lower() in FC05_DATA:
            value = FC05_DATA[data.lower()]
        elif bitval in BOOLEANS:          # por si otra versión de TShark lo imprime como bit
            value = BOOLEANS[bitval]
        elif re.fullmatch(r"[0-9a-fA-F]{4}", data):
            value = int(data, 16)         # valor ilegal según la especificación: el detector lo marca
        else:
            raise ValueError("FC05 sin estado de bobina interpretable")
    event = Event(float(timestamp), source, destination, int(unit), code,
                  int(address) if address else None, value, quantity, values_tuple,
                  int(src_port) if src_port else None,
                  int(stream) if stream else None, int(trans_id) if trans_id else None)
    event.validate()
    return event


def rejected_evidence(line: str) -> dict:
    """Evidencia mínima y validada de una fila que no se pudo interpretar (H2: nunca en silencio)."""
    values = (line.rstrip("\r\n").split("\t") + [""] * len(FIELDS))[:len(FIELDS)]
    row = dict(zip(FIELDS, values))

    def ip(text):
        try:
            return str(IPv4Address(text))
        except ValueError:
            return None
    try:
        ts = float(row["frame.time_epoch"])
        ts = ts if math.isfinite(ts) and 0 <= ts <= 1e12 else None
    except ValueError:
        ts = None
    functions = []
    for item in row["modbus.func_code"].split(",")[:16]:
        if item.isdigit() and int(item) <= 255:
            functions.append(int(item))
    stream = row["tcp.stream"]
    return {"timestamp": ts, "source": ip(row["ip.src"]), "destination": ip(row["ip.dst"]),
            "functions": functions, "adus_in_row": len(row["modbus.func_code"].split(",")),
            "flow_id": int(stream) if stream.isdigit() else None}


def command(binary: str, pcap: str) -> list[str]:
    args = [binary, "-n", "--only-protocols", PROTOCOLS,
            "-r", pcap, "-Y", "modbus && tcp.dstport == 502",
            "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a",
            "-E", "aggregator=,"]
    for field in FIELDS:
        args.extend(["-e", field])
    return args


ENCRYPTED_FILTER = "tcp.port == 802"


def encrypted_command(binary: str, pcap: str) -> list[str]:
    return [binary, "-n", "--only-protocols", "frame,eth,ethertype,vlan,ip,tcp", "-r", pcap,
            "-Y", ENCRYPTED_FILTER, "-T", "fields", "-E", "separator=/t",
            "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.stream"]


def encrypted_evidence(rows: list) -> list:
    """Un resumen por flujo TLS (no por paquete), con IP validadas."""
    flows = {}
    for row in rows:
        if len(row) != 4 or not row[3].isdigit():
            continue
        try:
            src, dst, ts = str(IPv4Address(row[1])), str(IPv4Address(row[2])), float(row[0])
        except ValueError:
            continue
        if not math.isfinite(ts):
            continue
        item = flows.setdefault(int(row[3]), {"flow_id": int(row[3]), "endpoints": sorted({src, dst}),
                                              "first_timestamp": ts, "packets": 0})
        item["packets"] += 1
    return list(flows.values())[:1000]


def decode(pcap: Path, binary: Path, approved_sha256: str, timeout_s: float | None = None,
           sandbox_mode: str = "require") -> tuple[list[Event], dict]:
    if timeout_s is not None:  # M5: sin valor, se escala con el tamaño de la captura
        timeout_s = finite(timeout_s, 1, 600, "timeout_s")
    if sandbox_mode not in ("require", "best-effort"):
        raise ValueError("sandbox debe ser require o best-effort")
    if os.name != "posix" or os.geteuid() == 0:
        raise ValueError("Adaptador requiere POSIX y usuario sin privilegios root")
    if not binary.is_absolute() or not binary.is_file():
        raise ValueError("Ruta absoluta a TShark requerida")
    binary = binary.resolve(strict=True)
    mode = binary.stat().st_mode
    if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("Binario con permisos no aceptables")
    if not re.fullmatch(r"[0-9a-f]{64}", approved_sha256):
        raise ValueError("SHA256 aprobado requerido (64 caracteres hex minúsculos)")
    with binary.open("rb") as stream:
        actual_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual_hash != approved_sha256:
        raise ValueError("SHA256 distinto del binario aprobado")
    pcap = pcap.absolute()
    packets = validate_pcap(pcap)
    with tempfile.TemporaryDirectory(prefix="ciberfox-") as folder:
        sandbox_dir = Path(folder)
        # Snapshot input to remove dependence on original after validation.
        local_pcap = sandbox_dir / "input.pcap"
        with pcap.open("rb") as source:
            snapshot = source.read(MAX_PCAP_BYTES + 1)
        if len(snapshot) > MAX_PCAP_BYTES:
            raise ValueError("PCAP creció durante la lectura")
        local_pcap.write_bytes(snapshot)
        pcap_sha256 = hashlib.sha256(snapshot).hexdigest()
        del snapshot
        packets = validate_pcap(local_pcap)
        if timeout_s is None:
            timeout_s = min(120.0, 25 + 2 * local_pcap.stat().st_size / 1024**2)
        for name in ("config", "plugins", "extcap"):
            (sandbox_dir / name).mkdir()
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
               "WIRESHARK_CONFIG_DIR": str(sandbox_dir / "config"),
               "WIRESHARK_PLUGIN_DIR": str(sandbox_dir / "plugins"),
               "WIRESHARK_EXTCAP_DIR": str(sandbox_dir / "extcap")}
        launcher = str(Path(__file__).resolve())

        require = sandbox_mode == "require"

        def run(args, flags=()):
            guard = ["--require"] if require else ["--best-effort"]
            with (sandbox_dir / "stdout").open("wb") as out, (sandbox_dir / "stderr").open("wb") as err:
                result = subprocess.run([sys.executable, "-I", launcher, "--limited-exec", *guard, *flags, *args],
                                        stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                        cwd=sandbox_dir, env=env, timeout=timeout_s, check=False)
            if result.returncode == SANDBOX_EXIT:
                raise ValueError("Sandbox de SO requerido no disponible aquí; use --sandbox best-effort bajo su responsabilidad")
            if result.returncode == HASH_EXIT:
                raise ValueError("El binario no coincide con el hash aprobado (cambió tras la verificación)")
            if result.returncode:
                # Do not echo untrusted parser diagnostics into terminal.
                raise ValueError(f"TShark falló ({result.returncode}); análisis incompleto")
            return sandbox_dir / "stdout"

        layers = json.loads(run([], ("--probe",)).read_text()[:8192])
        sandbox_report = {"mode": sandbox_mode, "layers": layers, "complete_for_platform": critical_ok(layers),
                          "filesystem_isolation": bool(layers.get("filesystem_isolation")),
                          "namespaces": bool(layers.get("user_net_namespaces"))}
        pinned = ("--sha256", actual_hash)

        version = check_version(run([str(binary), "--version"], pinned).read_text()[:8192])
        # H2: política explícita de tráfico cifrado (Modbus/TCP Security, TLS puerto 802). No se descifra;
        # se cuenta y se declara como NO inspeccionado para no reportar un análisis «completo».
        encrypted_out = run(encrypted_command(str(binary), str(local_pcap)), pinned).read_text()[:MAX_PCAP_BYTES]
        encrypted = [line.split("\t") for line in encrypted_out.splitlines()[:MAX_RECORDS] if line.strip()]
        rows = run(command(str(binary), str(local_pcap)), pinned)
        events, rejected = [], []
        with rows.open(encoding="utf-8", errors="strict") as stream:
            for _ in range(MAX_RECORDS + 1):
                line = stream.readline(8193)
                if not line:
                    break
                if len(line) > 8192 or len(events) + len(rejected) >= MAX_RECORDS:
                    raise ValueError("Salida de TShark excede límites")
                try:
                    events.append(parse_row(line))
                except ValueError:
                    rejected.append(rejected_evidence(line))
        return events, {"tshark_version": version, "binary_sha256": actual_hash, "pcap_sha256": pcap_sha256, "sandbox": sandbox_report,
                        "packets_in_file": packets, "parsed_requests": len(events),
                        "rejected_rows": len(rejected), "rejected_evidence": rejected,
                        "encrypted_packets_uninspected": len(encrypted),
                        "encrypted_evidence": encrypted_evidence(encrypted),
                        "status": "INCOMPLETE" if rejected or encrypted or not events else "SCOPED_ANALYSIS",
                        "scope": ("IPv4 Modbus/TCP destino 502, offline. Se interpretan FC01-06, FC15 y FC16; "
                                  "otras funciones -> UNSUPPORTED_CONTROL; filas no separables -> UNINSPECTED_*. "
                                  "Sin IPv6, BACnet, puertos alternativos ni tráfico cifrado (TLS puerto 802)"),
                        "production_ready": False}


# ======================================================================
# Bitácora de auditoría con cadena de hashes (H5)
# ======================================================================
def _canonical(record):
    return json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def audit_append(path: Path, record: dict) -> str:
    """Añade un registro encadenado (hash previo + registro). Detecta alteración, no truncamiento al final:
    guarde el último hash fuera del equipo. Cuenta de SO como identidad; NO es autenticación fuerte."""
    try:
        who = f"{getpass.getuser()} (uid={os.getuid()})"
    except (KeyError, OSError):
        who = f"uid={os.getuid()}"
    record = {"ts_epoch": round(time.time(), 3), "os_user": who, **record}
    import fcntl
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        size = os.fstat(fd).st_size
        previous = "0" * 64
        if size:
            tail = os.pread(fd, min(size, 65536), max(0, size - 65536)).rstrip(b"\n").split(b"\n")[-1]
            previous = json.loads(tail)["hash"]
        digest = hashlib.sha256((previous + _canonical(record)).encode("utf-8")).hexdigest()
        os.write(fd, (json.dumps({"prev": previous, "hash": digest, "record": record},
                                 ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    return digest


def audit_verify(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024**2:
        raise ValueError("Bitácora: archivo regular <=64 MiB, sin enlace simbólico")
    previous, count = "0" * 64, 0
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            row = json.loads(line)
            expected = hashlib.sha256((previous + _canonical(row["record"])).encode("utf-8")).hexdigest()
            if row["prev"] != previous or row["hash"] != expected:
                raise ValueError(f"Bitácora alterada en la línea {number}")
            previous, count = row["hash"], count + 1
    return {"entries": count, "last_hash": previous, "chain_ok": True}


# ======================================================================
# ciberfox/demo.py
# ======================================================================
"""Fixtures sintéticos escritos a disco. Nunca abre sockets."""



def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def write_fixture(path: Path):
    """4 conversaciones FC06 Ethernet/IPv4; IP de documentación RFC5737.

    Handshakes y checksums válidos; escrituras solo en un PCAP, no se envían.
    """
    events = [("192.0.2.10", 40), ("192.0.2.99", 50),
              ("192.0.2.10", 90), ("192.0.2.10", 60)]
    with path.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        index = 0
        for connection, (source, value) in enumerate(events):
            destination, port = "192.0.2.20", 40000 + connection
            pdu = struct.pack("!BHH", 6, 100, value)
            payload = struct.pack("!HHHB", connection + 1, 0, 1 + len(pdu), 1) + pdu
            frames = [(source, destination, port, 502, 1000, 0, 0x02, b""),
                      (destination, source, 502, port, 2000, 1001, 0x12, b""),
                      (source, destination, port, 502, 1001, 2001, 0x10, b""),
                      (source, destination, port, 502, 1001, 2001, 0x18, payload)]
            for src, dst, sport, dport, seq, ack, flags, data in frames:
                src_ip, dst_ip = socket.inet_aton(src), socket.inet_aton(dst)
                tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
                pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp) + len(data))
                tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + data)) + tcp[18:]
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(data), index,
                                 0x4000, 64, 6, 0, src_ip, dst_ip)
                ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
                frame = bytes.fromhex("0200000000200200000000100800") + ip + tcp + data
                out.write(struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame)))
                out.write(frame)
                index += 1


def simulate(modules=4):
    manager, detector = EnergyManager(), Detector()
    balances, timeline, alerts = [], [], []
    for second in range(600):
        hot = 60 if second < 200 else 70 if second < 400 else 33 if second < 500 else 80 if second < 550 else 60
        physics = illustrative_teg(hot, 30, modules)
        sample = PowerSample(physics["harvest_dc_w"], hot, 30, extra_cooling_w=0.15)
        balance = manager.step(sample)
        balances.append(balance)
        timeline.append({"second": second, "hot_c": hot, "cold_c": 30,
                         "harvest_dc_w": physics["harvest_dc_w"], **asdict(balance)})
        # Detector runs on every event regardless of energy mode.
        if second % 30 == 0:
            event = Event(second, "192.0.2.10", "192.0.2.20", 1, 6, 100, 40)
            if second == 120:
                event = Event(second, "192.0.2.99", "192.0.2.20", 1, 6, 100, 50)
            elif second == 270:
                event = Event(second, "192.0.2.10", "192.0.2.20", 1, 6, 100, 90)
            elif second == 450:
                event = Event(second, "192.0.2.10", "192.0.2.20", 1, 16)
            alerts.extend(detector.inspect(event))
    return {"label": "DATOS SIMULADOS — no son mediciones físicas",
            "modules_hypothetical": modules, "duration_s": 600,
            "events_inspected": detector.count, "alerts": alerts,
            "balance": summarize(balances), "timeline": timeline}


def dashboard(result):
    cases = result["cases"]
    sections = []
    for case in cases:
        balance = case["balance"]
        points = " ".join(f'{20 + row["second"]:.1f},{160 - min(row["harvest_dc_w"], 10)*12:.1f}'
                          for row in case["timeline"])
        rows = "".join(f"<tr><td>{html.escape(k)}</td><td>{v:.6f}</td></tr>"
                       for k, v in balance.items() if isinstance(v, (int, float)) and not isinstance(v, bool))
        alerts = "".join(f'<li><b>{html.escape(a["code"])}</b> — {html.escape(a["reason"])}</li>'
                         for a in case["alerts"])
        sections.append(f'''<section><h2>{case["modules_hypothetical"]} módulos hipotéticos</h2>
<div class="metrics"><div><strong>{balance["recovered_load_fraction"]:.1%}</strong>de la carga alimentada con energía recuperada</div>
<div><strong>{balance["grid_increment_vs_no_monitor_wh"]:.3f} Wh</strong>electricidad adicional frente a no instalar monitoreo</div></div>
<p>10 minutos simulados · 20 eventos inspeccionados · sin medición de hardware</p>
<svg viewBox="0 0 640 190" role="img" aria-label="Potencia recuperada simulada durante 600 segundos">
<path d="M20 20V160H620" stroke="#8aa" fill="none"/><line x1="20" y1="124" x2="620" y2="124" stroke="#efb35b" stroke-dasharray="5 5"/>
<polyline points="{points}" fill="none" stroke="#59ddc0" stroke-width="2"/>
<text x="25" y="18" fill="#dae">Potencia DC modelada (0–10 W); línea dorada: carga crítica 3 W</text>
<text x="20" y="182" fill="#dae">0 s</text><text x="565" y="182" fill="#dae">600 s</text></svg>
<p>El pico térmico de 500–550 s se rechaza por seguridad: potencia disponible no equivale a potencia aceptada.</p>
<h3>Alertas conservadas incluso con poco calor</h3><ul>{alerts}</ul>
<details><summary>Balance reproducible</summary><table>{rows}</table></details></section>''')
    page = '''<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>Ciberfox · laboratorio térmico OT</title><style>
body{font:16px/1.6 system-ui;background:#101b26;color:#e3edf6;max-width:1000px;margin:auto;padding:32px}
h1{font-size:40px;line-height:1.15}h2{font-size:26px}section{background:#192a39;padding:26px;border-radius:16px;margin:24px 0}
.tag{color:#101b26;background:#f6c36b;padding:7px 14px;border-radius:5px;display:inline-block;font-weight:700}
.metrics{display:flex;gap:28px;flex-wrap:wrap}.metrics div{flex:1;min-width:230px}.metrics strong{display:block;font-size:32px;color:#59ddc0}
svg{width:100%;margin-top:12px}td{padding:6px;border-bottom:1px solid #345;overflow-wrap:anywhere}table{width:100%;font-size:13px}
summary{cursor:pointer}footer{color:#a9bacb}</style><div class="tag">DATOS SIMULADOS</div>
<h1>Seguridad OT con recuperación de calor</h1><p>El respaldo mantiene la detección. El calor recuperado reduce una parte de la demanda eléctrica; no demuestra consumo neto cero.</p>
''' + "".join(sections) + '''<footer>Prototipo offline. No controla equipos, no captura redes y no garantiza disponibilidad física.
Comparación con igual carga de monitoreo. Factor de carbono y eficiencias hipotéticos. Carbono incorporado excluido.</footer></html>'''
    # M1: sin 'unsafe-inline'; el único <style> se autoriza por su hash SHA-256.
    css = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode()
    return page.replace("style-src 'unsafe-inline'", f"style-src 'sha256-{digest}'")


def run_demo(destination: Path):
    destination.mkdir(parents=True, exist_ok=False)
    result = {"label": "DATOS SIMULADOS", "cases": [simulate(4), simulate(32)]}
    (destination / "simulation.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    (destination / "panel.html").write_text(dashboard(result), encoding="utf-8")
    write_fixture(destination / "modbus_simulado.pcap")
    expected = {"label": "DATOS SIMULADOS", "packets": 16, "requests": 4,
                "expected_alert_codes": ["UNAUTHORIZED_COMMAND", "PROCESS_LIMIT"]}
    (destination / "pcap_expected.json").write_text(json.dumps(expected, indent=2), encoding="utf-8")
    return {"output": str(destination.resolve()), "label": "DATOS SIMULADOS",
            "cases": [{"modules": c["modules_hypothetical"], **c["balance"]} for c in result["cases"]]}


# ======================================================================
# ciberfox/__main__.py (CLI)
# ======================================================================
def replay_power(path, policy=None):
    """CSV con potencia DC ya medida/estimada por un sistema externo.

    Este comando NO mide hardware ni certifica procedencia/calibración.
    Intervalos entre muestras <=5s; cualquier hueco invalida el replay.
    """
    if not path.is_file() or path.stat().st_size > 2 * 1024**2:
        raise ValueError("CSV debe ser regular y <=2 MiB")
    manager, balances, previous = EnergyManager(**(policy.energy_manager if policy else {})), [], None
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        required = {"timestamp_s", "harvest_dc_w", "hot_c", "cold_c", "extra_cooling_w"}
        if set(reader.fieldnames or []) != required:
            raise ValueError("Columnas requeridas: " + ",".join(sorted(required)))
        for index, row in enumerate(reader):
            if index >= 10000:
                raise ValueError("Máximo 10000 muestras")
            current = finite(float(row["timestamp_s"]), 0, 1e12, "timestamp_s")
            sample = PowerSample(*(float(row[k]) for k in ("harvest_dc_w", "hot_c", "cold_c")),
                                 extra_cooling_w=float(row["extra_cooling_w"]))
            sample.validate()
            if previous:
                prior_time, prior_sample = previous
                seconds = current - prior_time
                if not 0 < seconds <= 5:
                    raise ValueError("Telemetría desordenada o hueco >5s: replay incompleto")
                balances.append(manager.step(prior_sample, seconds))
            previous = (current, sample)
    if len(balances) < 1:
        raise ValueError("Se requieren al menos dos muestras")
    return {"label": f"TELEMETRÍA EXTERNA NO VERIFICADA; carga de {manager.core:g} W y almacenamiento modelados",
            "physical_control": False, "balance": summarize(balances, **(policy.energy_summary if policy else {}))}


def main():
    parser = argparse.ArgumentParser(description="Laboratorio Ciberfox offline; no conecta redes OT")
    subs = parser.add_subparsers(dest="action", required=True)
    demo = subs.add_parser("demo")
    demo.add_argument("--out", type=Path, required=True, help="Directorio nuevo; no sobrescribe")
    analyze = subs.add_parser("analyze-pcap")
    analyze.add_argument("--pcap", type=Path, required=True)
    analyze.add_argument("--tshark", type=Path, required=True)
    analyze.add_argument("--approved-sha256", required=True)
    analyze.add_argument("--timeout", type=float, default=None, help="Segundos máximos por ejecución de TShark (1-600); por defecto escala con el tamaño")
    analyze.add_argument("--policy", type=Path, help="Política JSON por despliegue (allowlist, mapas, umbrales)")
    analyze.add_argument("--policy-sha256", help="SHA256 aprobado del archivo de política")
    analyze.add_argument("--audit-log", type=Path, help="Bitácora JSONL encadenada por hash")
    analyze.add_argument("--sandbox", choices=("require", "best-effort"), default="require")
    replay = subs.add_parser("replay-power")
    replay.add_argument("--csv", type=Path, required=True)
    replay.add_argument("--policy", type=Path)
    replay.add_argument("--policy-sha256")
    verify = subs.add_parser("audit-verify")
    verify.add_argument("--log", type=Path, required=True)
    subs.add_parser("test")
    args = parser.parse_args()
    try:
        if args.action == "test":
            import unittest
            run = unittest.main(module=sys.modules[__name__], argv=["ciberfox", "-v"], exit=False)
            return 0 if run.result.wasSuccessful() else 1
        if args.action == "demo":
            result = run_demo(args.out)
        elif args.action == "replay-power":
            result = replay_power(args.csv, load_policy(args.policy, args.policy_sha256) if args.policy else None)
        elif args.action == "audit-verify":
            result = audit_verify(args.log)
        else:
            try:
                policy = load_policy(args.policy, args.policy_sha256) if args.policy else None
                events, health = decode(args.pcap, args.tshark, args.approved_sha256, args.timeout, args.sandbox)
            except Exception as exc:
                if args.audit_log:
                    try:
                        audit_append(args.audit_log, {"action": "analyze-pcap", "status": "ERROR",
                                                      "error": type(exc).__name__})
                    except Exception:
                        pass
                raise
            detector = Detector(policy)
            alerts = [alert for event in events for alert in detector.inspect(event)]
            alerts += [detector.uninspected(evidence) for evidence in health.pop("rejected_evidence")]
            alerts += [{"code": "ENCRYPTED_UNINSPECTED",
                        "reason": "Flujo en el puerto 802 (Modbus/TCP Security): cifrado, sin inspección de comandos",
                        "event": {**flow, "timestamp": flow["first_timestamp"]},
                        "action": "REVISIÓN HUMANA; inspeccionar en el terminador TLS o con claves autorizadas"}
                       for flow in health.pop("encrypted_evidence")]
            alerts.sort(key=lambda item: item["event"].get("timestamp") or 0)
            health["policy_sha256"] = policy.sha256 if policy else "default-laboratorio"
            result = {"health": health, "alerts": alerts, "physical_control": False}
            if args.audit_log:  # si no se puede auditar, el análisis falla (cierre seguro)
                counts = {}
                for item in alerts:
                    counts[item["code"]] = counts.get(item["code"], 0) + 1
                audit_append(args.audit_log, {
                    "action": "analyze-pcap", "status": health["status"], "pcap_sha256": health["pcap_sha256"],
                    "binary_sha256": health["binary_sha256"], "policy_sha256": health["policy_sha256"],
                    "parsed_requests": health["parsed_requests"], "rejected_rows": health["rejected_rows"],
                    "alert_counts": counts,
                    "alerts_sha256": hashlib.sha256(_canonical(alerts).encode("utf-8")).hexdigest()})
            print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
            return 2 if health["status"] == "INCOMPLETE" else 0
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        return 0
    except (ValueError, OSError, subprocess.TimeoutExpired, UnicodeError, csv.Error) as exc:
        print(json.dumps({"status": "INCOMPLETE", "error": str(exc), "physical_control": False},
                         ensure_ascii=False), file=sys.stderr)
        return 2
    except Exception as exc:  # M2: error genérico, sin stacktrace
        print(json.dumps({"status": "INCOMPLETE", "error": "Error interno: " + type(exc).__name__,
                          "physical_control": False}, ensure_ascii=False), file=sys.stderr)
        return 2


# ======================================================================
# tests/test_system.py
# ======================================================================
class EnergyTests(unittest.TestCase):
    def test_no_temperature_gradient_no_generation(self):
        self.assertEqual(illustrative_teg(30, 30)["harvest_dc_w"], 0)
        self.assertEqual(illustrative_teg(20, 30)["harvest_dc_w"], 0)

    def test_generation_below_carnot(self):
        for temperature in (31, 40, 60, 90):
            result = illustrative_teg(temperature, 30)
            self.assertLessEqual(result["teg_gross_w"], result["q_hot_assumed_w"] * result["carnot_upper_bound"])

    def test_conservation_random_trace(self):
        rng = random.Random(21)
        manager = EnergyManager()
        for _ in range(1000):
            before = manager.stored
            result = manager.step(PowerSample(rng.uniform(0, 10), 60, 30), rng.uniform(.01, 5))
            self.assertAlmostEqual(result.load_wh, result.recovered_to_load_wh + result.grid_dc_wh)
            self.assertAlmostEqual(before + result.harvest_accepted_wh + result.grid_dc_wh,
                                   result.load_wh + result.stored_wh + result.curtailed_wh + result.storage_loss_wh)
            self.assertGreaterEqual(manager.stored, -1e-12)
            self.assertLessEqual(manager.stored, manager.capacity + 1e-12)

    def test_no_harvest_does_not_disable_detection_load(self):
        result = EnergyManager().step(PowerSample(0, 30, 30), 60)
        self.assertEqual(result.mode, "CORE_ONLY")
        self.assertAlmostEqual(result.grid_dc_wh, 3 / 60)
        self.assertEqual(result.recovered_to_load_wh, 0)

    def test_thermal_fault_keeps_backup(self):
        result = EnergyManager().step(PowerSample(20, 80, 30), 1)
        self.assertEqual(result.warning, "THERMAL_REVIEW_REQUIRED")
        self.assertEqual(result.harvest_accepted_wh, 0)
        self.assertEqual(result.grid_dc_wh, result.load_wh)

    def test_stale_telemetry_cannot_claim_generation(self):
        result = EnergyManager().step(PowerSample(20, 60, 30, age_s=6))
        self.assertEqual(result.warning, "STALE_POWER_TELEMETRY")
        self.assertEqual(result.harvest_accepted_wh, 0)

    def test_nan_inf_and_negative_rejected(self):
        for value in (math.nan, math.inf, -1):
            with self.assertRaises(ValueError):
                EnergyManager().step(PowerSample(value, 60, 30))

    def test_cooling_can_erase_benefit(self):
        result = EnergyManager().step(PowerSample(0.1, 60, 30, extra_cooling_w=1), 60)
        self.assertLess(summarize([result])["grid_saving_vs_same_load_wh"], 0)

    def test_optional_work_only_after_buffer_charge(self):
        manager = EnergyManager()
        self.assertEqual(manager.step(PowerSample(10, 60, 30)).mode, "CORE_ONLY")
        for _ in range(150):
            last = manager.step(PowerSample(10, 60, 30))
        self.assertEqual(last.mode, "CORE_PLUS_REPORTS")
        self.assertEqual(manager.step(PowerSample(0, 30, 30)).mode, "CORE_ONLY")


class DetectionTests(unittest.TestCase):
    def test_authorized_and_boundary_values(self):
        detector = Detector()
        for value in (20, 40, 60):
            self.assertEqual(detector.inspect(Event(1, "192.0.2.10", "192.0.2.20", 1, 6, 100, value)), [])

    def test_authorized_source_does_not_bypass_process_limit(self):
        alerts = Detector().inspect(Event(1, "192.0.2.10", "192.0.2.20", 1, 6, 100, 90))
        self.assertEqual(alerts[0]["code"], "PROCESS_LIMIT")

    def test_untrusted_source_and_unknown_register(self):
        alerts = Detector().inspect(Event(1, "192.0.2.99", "192.0.2.20", 1, 6, 200, 40))
        self.assertEqual({a["code"] for a in alerts}, {"UNAUTHORIZED_COMMAND", "UNAPPROVED_REGISTER"})

    def test_unsupported_write_is_not_silent(self):
        alerts = Detector().inspect(Event(1, "192.0.2.10", "192.0.2.20", 1, 16))
        self.assertEqual(alerts[0]["code"], "UNSUPPORTED_CONTROL")

    def test_same_alerts_under_different_energy_budgets(self):
        small, large = simulate(4), simulate(32)
        self.assertEqual(small["alerts"], large["alerts"])
        self.assertEqual(small["events_inspected"], 20)
        self.assertEqual(len(small["alerts"]), 3)
        self.assertGreater(small["balance"]["grid_increment_vs_no_monitor_wh"], 0)


class AdapterTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix" and os.geteuid() != 0, "POSIX no root")
    def test_subprocess_pipeline_with_explicit_test_double(self):
        # Exercises orchestration, NOT genuine Wireshark dissection.
        with tempfile.TemporaryDirectory() as folder:
            binary, pcap = Path(folder) / "fake_tshark", Path(folder) / "fixture.pcap"
            binary.write_text("#!" + sys.executable + "\nimport sys\n"
                              "if '--version' in sys.argv:\n print('TShark (Wireshark) 4.6.9')\n"
                              "elif 'tcp.port == 802' in sys.argv:\n pass\n"
                              "else:\n print('1\\t192.0.2.99\\t192.0.2.20\\t1\\t6\\t100\\t50\\t\\t\\t\\t\\t\\t0\\t1')\n")
            binary.chmod(0o500)
            write_fixture(pcap)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            events, health = decode(pcap, binary, digest, sandbox_mode="best-effort")
            self.assertEqual(health["status"], "SCOPED_ANALYSIS")
            self.assertEqual(Detector().inspect(events[0])[0]["code"], "UNAUTHORIZED_COMMAND")
            with self.assertRaises(ValueError):
                decode(pcap, binary, "0" * 64)

    def test_documented_fields_and_no_shell(self):
        args = command("/opt/tshark", "/tmp/demo.pcap")
        self.assertIn("modbus.regval_uint16", args)
        self.assertIn("--only-protocols", args)
        self.assertNotIn("modbus.reg16", args)
        self.assertNotIn("-i", args)
        self.assertNotIn("-V", args)

    def test_version_gate(self):
        self.assertEqual(check_version("TShark (Wireshark) 4.6.9 (build)"), "4.6.9")
        for version in ("4.6.8", "4.7.0", "4.6.9rc1", "4.6.9-rc1", "4.4.0"):
            with self.assertRaises(ValueError):
                check_version("TShark (Wireshark) " + version)

    def test_reject_multi_pdu_missing_and_nonfinite(self):
        for line in ("1\t192.0.2.10\t192.0.2.20\t1\t6,6\t100\t40\t\t\t\t\t\t\t",
                     "nan\t192.0.2.10\t192.0.2.20\t1\t6\t100\t40\t\t\t\t\t\t\t",
                     "1\t192.0.2.10\t192.0.2.20\t1\t6\t100\t\t\t\t\t\t\t\t"):
            with self.assertRaises(ValueError):
                parse_row(line)

    def test_parse_single_request(self):
        event = parse_row("1.5\t192.0.2.10\t192.0.2.20\t1\t6\t100\t40\t\t\t\t\t\t\t\n")
        self.assertEqual(event.value, 40)

    def test_fixture_valid_and_truncation_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.pcap"
            write_fixture(path)
            self.assertEqual(validate_pcap(path), 16)
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaises(ValueError):
                validate_pcap(path)

    def test_fixture_ip_and_tcp_checksums(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.pcap"
            write_fixture(path)
            with path.open("rb") as stream:
                stream.read(24)
                while record := stream.read(16):
                    included = struct.unpack("<IIII", record)[2]
                    frame = stream.read(included)
                    ip, tcp = frame[14:34], frame[34:]
                    self.assertEqual(checksum(ip), 0)
                    pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
                    self.assertEqual(checksum(pseudo + tcp), 0)

    def test_power_csv_gap_invalidates_accounting(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "power.csv"
            header = "timestamp_s,harvest_dc_w,hot_c,cold_c,extra_cooling_w\n"
            path.write_text(header + "0,1,60,30,0.1\n1,1,60,30,0.1\n")
            self.assertIn("balance", replay_power(path))
            path.write_text(header + "0,1,60,30,0.1\n10,1,60,30,0.1\n")
            with self.assertRaises(ValueError):
                replay_power(path)


class AuditFixTests(unittest.TestCase):
    def test_version_gate_is_anchored(self):
        for text in ("junk TShark (Wireshark) 4.6.9", "x\nTShark (Wireshark) 4.6.9"):
            with self.assertRaises(ValueError):
                check_version(text)

    def test_csp_hash_replaces_unsafe_inline(self):
        page = dashboard({"cases": [simulate(4)]})
        css = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
        digest = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
        self.assertNotIn("unsafe-inline", page)
        self.assertIn(f"style-src 'sha256-{digest}'", page)
        self.assertIn("object-src 'none'", page)

    def test_timeout_validated(self):
        with self.assertRaises(ValueError):
            decode(Path("/x.pcap"), Path("/x"), "0" * 64, timeout_s=0)


class RemediationTests(unittest.TestCase):
    def row(self, *cols):
        return "\t".join(cols)

    def test_parse_fc16_list_and_fc15_fc05(self):
        e = parse_row("1\t192.0.2.10\t192.0.2.20\t1\t16\t100\t40,50\t\t2\t\t40000\t\t3\t9")
        self.assertEqual((e.values, e.quantity, e.src_port, e.flow_id, e.transaction_id), ((40, 50), 2, 40000, 3, 9))
        e = parse_row("1\t192.0.2.10\t192.0.2.20\t1\t5\t7\t\tTrue\t\t\t40001\t\t\t")
        self.assertEqual(e.value, 1)
        e = parse_row("1\t192.0.2.10\t192.0.2.20\t1\t15\t7\t\t\t\t8\t40001\t\t\t")
        self.assertEqual(e.quantity, 8)
        for bad in ("1\t192.0.2.10\t192.0.2.20\t1\t16,16\t100\t40,50\t\t2\t\t1\t\t\t",
                    "1\t192.0.2.10\t192.0.2.20\t1\t6\t100\t40,50\t\t\t\t1\t\t\t",
                    "1\t192.0.2.10\t192.0.2.20\t1\t5\t7\t\t\t\t\t1\t\t\t"):
            with self.assertRaises(ValueError):
                parse_row(bad)

    def test_new_fields_in_command(self):
        args = command("/opt/tshark", "/tmp/x.pcap")
        for field in ("modbus.bitval", "modbus.word_cnt", "modbus.bit_cnt", "tcp.srcport"):
            self.assertIn(field, args)

    def test_fc05_fc15_fc16_detection(self):
        policy = default_policy()
        policy = Policy(policy.allowed_sources, policy.allowed_readers, policy.targets,
                        {100: (20, 60, "a"), 101: (0, 10, "b")}, {7: (frozenset({0, 1}), "c"), 8: (frozenset({0}), "d")}, {}, {})
        det = Detector(policy)
        ev = lambda f, **k: Event(1, "192.0.2.10", "192.0.2.20", 1, f, **k)
        self.assertEqual(det.inspect(ev(5, address=7, value=1)), [])
        self.assertEqual(det.inspect(ev(5, address=8, value=1))[0]["code"], "PROCESS_LIMIT")
        self.assertEqual(det.inspect(ev(5, address=9, value=1))[0]["code"], "UNAPPROVED_COIL")
        self.assertEqual(det.inspect(ev(16, address=100, quantity=2, values=(40, 5))), [])
        self.assertEqual(det.inspect(ev(16, address=100, quantity=2, values=(90, 5)))[0]["code"], "PROCESS_LIMIT")
        self.assertEqual(det.inspect(ev(16, address=100, quantity=3, values=(40, 5, 1)))[0]["code"], "UNAPPROVED_REGISTER")
        self.assertEqual(det.inspect(ev(16, address=100, quantity=2, values=(40,)))[0]["code"], "MALFORMED_WRITE")
        self.assertEqual(det.inspect(ev(15, address=7, quantity=2, values=(1, 0))), [])
        self.assertEqual(det.inspect(ev(15, address=7, quantity=3))[0]["code"], "UNAPPROVED_COIL")
        self.assertEqual(det.inspect(ev(5))[0]["code"], "UNSUPPORTED_CONTROL")
        self.assertEqual(det.inspect(ev(23))[0]["code"], "UNSUPPORTED_CONTROL")
        bad = det.inspect(Event(1, "192.0.2.99", "192.0.2.20", 1, 16, 100, None, 1, (40,)))
        self.assertEqual([a["code"] for a in bad], ["UNAUTHORIZED_COMMAND"])

    def test_unauthorized_read_alert(self):
        det = Detector()
        self.assertEqual(det.inspect(Event(1, "192.0.2.10", "192.0.2.20", 1, 3, 100)), [])
        self.assertEqual(det.inspect(Event(1, "192.0.2.99", "192.0.2.20", 1, 3, 100))[0]["code"], "UNAUTHORIZED_READ")

    def test_policy_loading_and_energy_params(self):
        good = {"allowed_sources": ["192.0.2.50"], "targets": [["192.0.2.60", 2]],
                "registers": {"10": [1, 5, "bomba"]}, "coils": {"3": [[0, 1], "valvula"]},
                "energy": {"core_w": 2.0, "hot_limit_c": 70, "kg_co2e_kwh": 0.2}}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text(json.dumps(good))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            policy = load_policy(path, digest)
            det = Detector(policy)
            self.assertEqual(det.inspect(Event(1, "192.0.2.50", "192.0.2.60", 2, 6, 10, 3)), [])
            self.assertEqual(det.inspect(Event(1, "192.0.2.50", "192.0.2.60", 2, 6, 10, 9))[0]["code"], "PROCESS_LIMIT")
            self.assertEqual(policy.energy_manager["hot_limit_c"], 70)
            with self.assertRaises(ValueError):
                load_policy(path, "0" * 64)
            for mutation in ({"extra": 1}, {"allowed_sources": ["no-ip"]}, {"registers": {"10": [9, 1, "x"]}},
                             {"energy": {"core_w": -1}}, {"coils": {"3": [[2], "x"]}}, {"targets": [["192.0.2.1", 999]]}):
                path.write_text(json.dumps({**good, **mutation}))
                with self.assertRaises(ValueError):
                    load_policy(path)
            path.write_text('{"allowed_sources": NaN}')
            with self.assertRaises(ValueError):
                load_policy(path)
            link = Path(folder) / "link.json"
            path.write_text(json.dumps(good))
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                load_policy(link)
            csv_path = Path(folder) / "p.csv"
            csv_path.write_text("timestamp_s,harvest_dc_w,hot_c,cold_c,extra_cooling_w\n0,1,60,30,0\n1,1,60,30,0\n")
            out = replay_power(csv_path, policy)
            self.assertIn("2 W", out["label"])
            self.assertEqual(out["balance"]["carbon_factor_assumed_kg_kwh"], 0.2)

    def test_energy_limits_configurable(self):
        self.assertEqual(EnergyManager(hot_limit_c=50).step(PowerSample(5, 60, 30)).warning, "THERMAL_REVIEW_REQUIRED")
        self.assertEqual(EnergyManager(stale_s=1).step(PowerSample(5, 60, 30, age_s=2)).warning, "STALE_POWER_TELEMETRY")
        with self.assertRaises(ValueError):
            EnergyManager(hot_limit_c=math.nan)

    def test_audit_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "audit.jsonl"
            audit_append(log, {"action": "a", "status": "OK"})
            last = audit_append(log, {"action": "b", "status": "OK"})
            self.assertEqual(audit_verify(log), {"entries": 2, "last_hash": last, "chain_ok": True})
            self.assertEqual(oct(log.stat().st_mode & 0o777), "0o600")
            log.write_text(log.read_text().replace('"a"', '"x"'))
            with self.assertRaises(ValueError):
                audit_verify(log)

    @unittest.skipUnless(sys.platform.startswith("linux"), "seccomp solo en Linux")
    def test_sandbox_blocks_network_and_checks_hash(self):
        import subprocess as sp
        me, python = str(Path(__file__).resolve()), os.path.realpath(sys.executable)
        base = [sys.executable, "-I", me, "--limited-exec", "--require"]
        probe = sp.run(base + ["--probe"], capture_output=True, text=True)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        layers = json.loads(probe.stdout)
        self.assertTrue(layers["no_new_privs"] and layers["seccomp_network_deny"])
        blocked = sp.run(base + [python, "-c", "import socket; socket.socket()"], capture_output=True, text=True)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("PermissionError", blocked.stderr)
        digest = hashlib.sha256(Path(python).read_bytes()).hexdigest()
        ok = sp.run(base + ["--sha256", digest, python, "-c", "print('hola')"], capture_output=True, text=True)
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "hola"))
        bad = sp.run(base + ["--sha256", "0" * 64, python, "-c", "print('hola')"], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 98)


class RealTsharkFieldTests(unittest.TestCase):
    """Filas copiadas de la salida de TShark 4.6.9 REAL (22-oct-2026) sobre solicitudes sintéticas."""
    HEAD = "1700000003.000000000\t192.0.2.10\t192.0.2.20\t1\t"

    def policy(self):
        base = default_policy()
        return Policy(base.allowed_sources, base.allowed_readers, base.targets, {100: (20, 60, "bomba")},
                      {7: (frozenset({0, 1}), "respaldo"), 8: (frozenset({1}), "valvula"), 9: (frozenset({0, 1}), "x")}, {}, {})

    def test_fc05_value_comes_from_modbus_data(self):
        on = parse_row(self.HEAD + "5\t7\t\t\t\t\t41000\tff00\t0\t1")
        off = parse_row(self.HEAD + "5\t8\t\t\t\t\t41001\t0000\t1\t2")
        self.assertEqual((on.value, off.value), (1, 0))
        det = Detector(self.policy())
        self.assertEqual(det.inspect(on), [])
        self.assertEqual(det.inspect(off)[0]["code"], "PROCESS_LIMIT")   # cerrar válvula prohibido
        illegal = parse_row(self.HEAD + "5\t7\t\t\t\t\t41000\t1234\t0\t1")
        self.assertEqual(det.inspect(illegal)[0]["code"], "MALFORMED_WRITE")

    def test_fc15_bits_are_validated(self):
        event = parse_row(self.HEAD + "15\t7\t\tTrue,False,True\t\t3\t41002\t\t2\t3")
        self.assertEqual(event.values, (1, 0, 1))
        alerts = Detector(self.policy()).inspect(event)
        self.assertEqual([a["code"] for a in alerts], ["PROCESS_LIMIT"])   # bobina 8 = 0 no permitido
        with self.assertRaises(ValueError):
            parse_row(self.HEAD + "15\t7\t\tTrue,maybe\t\t2\t41002\t\t2\t3")

    def test_pipelined_write_is_never_silent(self):
        line = "1700000019.000000000\t192.0.2.99\t192.0.2.20\t1,1\t3,6\t100,100\t55\t\t1\t\t41004\t\t4\t5,6"
        with self.assertRaises(ValueError):
            parse_row(line)
        alert = Detector().uninspected(rejected_evidence(line))
        self.assertEqual(alert["code"], "UNINSPECTED_CONTROL")
        self.assertEqual(alert["event"]["functions"], [3, 6])
        self.assertFalse(alert["event"]["source_authorized_for_writes"])
        reads = Detector().uninspected(rejected_evidence(line.replace("3,6", "3,4")))
        self.assertEqual(reads["code"], "UNINSPECTED_REQUEST")

    def test_rejected_evidence_sanitizes_garbage(self):
        evidence = rejected_evidence("nan\tno-ip\t\t\tx,6\n")
        self.assertEqual((evidence["timestamp"], evidence["source"], evidence["functions"]), (None, None, [6]))


class AlertFatigueTests(unittest.TestCase):
    def test_unauthorized_reads_are_aggregated_per_window(self):
        det = Detector()
        first = det.inspect(Event(1, "192.0.2.99", "192.0.2.20", 1, 3, 100))
        self.assertEqual([a["code"] for a in first], ["UNAUTHORIZED_READ"])
        flood = []
        for second in range(2, 2002):
            flood += det.inspect(Event(second / 100, "192.0.2.99", "192.0.2.20", 1, 3, 100))
        self.assertEqual([a["code"] for a in flood], ["READ_FLOOD"])        # una sola escalada
        self.assertEqual(first[0]["occurrences"], 2001)
        later = det.inspect(Event(200, "192.0.2.99", "192.0.2.20", 1, 4, 0))
        self.assertEqual(len(later), 1)                                     # nueva ventana
        other = det.inspect(Event(201, "192.0.2.98", "192.0.2.20", 1, 3, 100))
        self.assertEqual(len(other), 1)                                     # otro origen
        writes = det.inspect(Event(202, "192.0.2.99", "192.0.2.20", 1, 6, 100, 50))
        self.assertEqual([a["code"] for a in writes], ["UNAUTHORIZED_COMMAND"])  # escrituras nunca se agregan


class EncryptedPolicyTests(unittest.TestCase):
    def test_encrypted_flows_summarized_and_sanitized(self):
        rows = [["1.0", "192.0.2.10", "192.0.2.20", "7"], ["2.0", "192.0.2.20", "192.0.2.10", "7"],
                ["nan", "192.0.2.10", "192.0.2.20", "8"], ["3.0", "no-ip", "192.0.2.20", "9"], ["x"]]
        flows = encrypted_evidence(rows)
        self.assertEqual(len(flows), 1)
        self.assertEqual((flows[0]["flow_id"], flows[0]["packets"]), (7, 2))
        self.assertIn("tcp.port == 802", encrypted_command("/opt/tshark", "/tmp/x.pcap"))


class SandboxHardeningTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() != 0, "Linux sin root")
    def test_landlock_blocks_files_outside_workdir(self):
        import subprocess as sp
        me, python = str(Path(__file__).resolve()), os.path.realpath(sys.executable)
        with tempfile.TemporaryDirectory() as work, tempfile.TemporaryDirectory(dir=Path.home()) as secret_dir:
            secret = Path(secret_dir) / "secreto.txt"
            secret.write_text("x")
            code = (f"import pathlib; pathlib.Path('ok.txt').write_text('1');"
                    f"open({str(secret)!r}).read()")
            run = sp.run([sys.executable, "-I", me, "--limited-exec", "--require", python, "-c", code],
                         cwd=work, capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("PermissionError", run.stderr)
            self.assertTrue((Path(work) / "ok.txt").exists())   # el directorio de trabajo sí es escribible

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() != 0, "Linux sin root")
    def test_probe_reports_all_linux_layers(self):
        import subprocess as sp
        me = str(Path(__file__).resolve())
        with tempfile.TemporaryDirectory() as work:
            out = sp.run([sys.executable, "-I", me, "--limited-exec", "--probe"], cwd=work,
                         capture_output=True, text=True)
        layers = json.loads(out.stdout)
        for key in ("no_new_privs", "seccomp_network_deny", "filesystem_isolation", "user_net_namespaces"):
            self.assertIn(key, layers)

    def test_seccomp_lists_cover_io_uring_and_process_vm(self):
        for arch in DENY_SYSCALLS.values():
            self.assertTrue({425, 426, 427} <= set(arch[1]))
        self.assertTrue({310, 311} <= set(DENY_SYSCALLS["x86_64"][1]))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--limited-exec":
        limited_exec_main()
    raise SystemExit(main())
