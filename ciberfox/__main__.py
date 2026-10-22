import argparse
import csv
import json
from pathlib import Path
import subprocess
import sys

from .demo import run_demo
from .detector import Detector
from .energy import EnergyManager, PowerSample, summarize, finite
from .tshark_adapter import decode


def replay_power(path):
    """CSV con potencia DC ya medida/estimada por un sistema externo.

    Este comando NO mide hardware ni certifica procedencia/calibración.
    Intervalos entre muestras <=5s; cualquier hueco invalida el replay.
    """
    if not path.is_file() or path.stat().st_size > 2 * 1024**2:
        raise ValueError("CSV debe ser regular y <=2 MiB")
    manager, balances, previous = EnergyManager(), [], None
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
    return {"label": "TELEMETRÍA EXTERNA NO VERIFICADA; carga de 3 W y almacenamiento modelados",
            "physical_control": False, "balance": summarize(balances)}


def main():
    parser = argparse.ArgumentParser(description="Laboratorio Ciberfox offline; no conecta redes OT")
    subs = parser.add_subparsers(dest="action", required=True)
    demo = subs.add_parser("demo")
    demo.add_argument("--out", type=Path, required=True, help="Directorio nuevo; no sobrescribe")
    analyze = subs.add_parser("analyze-pcap")
    analyze.add_argument("--pcap", type=Path, required=True)
    analyze.add_argument("--tshark", type=Path, required=True)
    analyze.add_argument("--approved-sha256", required=True)
    replay = subs.add_parser("replay-power")
    replay.add_argument("--csv", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "demo":
            result = run_demo(args.out)
        elif args.action == "replay-power":
            result = replay_power(args.csv)
        else:
            events, health = decode(args.pcap, args.tshark, args.approved_sha256)
            detector = Detector()
            alerts = [alert for event in events for alert in detector.inspect(event)]
            result = {"health": health, "alerts": alerts, "physical_control": False}
            print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
            return 2 if health["status"] == "INCOMPLETE" else 0
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        return 0
    except (ValueError, OSError, subprocess.TimeoutExpired, UnicodeError, csv.Error) as exc:
        print(json.dumps({"status": "INCOMPLETE", "error": str(exc), "physical_control": False},
                         ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
