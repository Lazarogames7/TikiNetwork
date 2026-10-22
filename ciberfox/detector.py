"""Reglas de laboratorio, sin conexiones ni comandos a PLCs."""
from dataclasses import dataclass, asdict
from ipaddress import IPv4Address
from .energy import finite


@dataclass(frozen=True)
class Event:
    timestamp: float
    source: str
    destination: str
    unit: int
    function: int
    address: int | None = None
    value: int | None = None

    def validate(self):
        finite(self.timestamp, 0, 1e12, "timestamp")
        IPv4Address(self.source)
        IPv4Address(self.destination)
        for name, limit in (("unit", 255), ("function", 255)):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= limit:
                raise ValueError(name)
        for name in ("address", "value"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or not 0 <= value <= 65535):
                raise ValueError(name)
        if self.function == 6 and (self.address is None or self.value is None):
            raise ValueError("FC06 necesita dirección y valor")


class Detector:
    """Allowlist demo. Valores crudos sin signo; NO configuración de una planta."""
    def __init__(self):
        self.allowed = {"192.0.2.10"}
        self.target = ("192.0.2.20", 1)
        self.registers = {100: (20, 60, "consigna_bomba_demo")}
        self.count = 0

    def inspect(self, event: Event) -> list[dict]:
        event.validate()
        self.count += 1
        alerts = []

        def alert(code, reason):
            alerts.append({"code": code, "reason": reason, "event": asdict(event),
                           "action": "REVISIÓN HUMANA; sin bloqueo automático"})

        if (event.destination, event.unit) != self.target:
            alert("UNEXPECTED_ASSET", "Destino o unidad fuera de la política de laboratorio")
        # Read-only Modbus functions have no write semantics validated here.
        if event.function in (1, 2, 3, 4):
            return alerts
        if event.source not in self.allowed:
            alert("UNAUTHORIZED_COMMAND", "Origen no autorizado para comandos de control")
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
