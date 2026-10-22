# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ciberfox contributors
"""Orquestador del laboratorio Ciberfox. DATOS SIMULADOS.

Por cada modo (flat = red plana, segmented = microsegmentación):
  1. levanta la topología y los servicios de cada host
  2. mide superficie de ataque (sondeo TCP de todos contra todos)
  3. mide latencia Modbus SCADA→PLC a través del gateway
  4. captura en el gateway frente al PLC (equivalente a un TAP) mientras corren
     la operación normal y los 11 ataques programados
  5. ejecuta el analizador REAL del equipo (python -m ciberfox analyze-pcap con
     TShark) como usuario sin privilegios y lo compara contra la verdad de terreno
  6. alimenta el replay energético con la temperatura de la planta simulada

Uso (root, Linux):  python3 lab/run_lab.py --tshark /ruta/tshark --out lab_result
"""
import argparse
import csv
import hashlib
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO))
import topology as topo  # noqa: E402
try:  # paquete original (ciberfox/) o versión de un solo archivo (ciberfox.py)
    from ciberfox.detector import Detector, Event  # noqa: E402
    from ciberfox.energy import illustrative_teg  # noqa: E402
except ImportError:
    from ciberfox import Detector, Event, illustrative_teg  # noqa: E402
POLICY = None

PY = sys.executable
SCHEDULE = [  # (segundo, ataque)
    (15, "A1"), (25, "A4"), (40, "A3"), (55, "A7"), (62, "A6"), (70, "A8"),
    (78, "A9"), (86, "A10"), (94, "A11"), (105, "A2"), (140, "R1"), (150, "A5"),
]
DURATION = 200
NORMAL_SOURCES = {"192.0.2.10", "192.0.2.11"}


def nsx(host, *args):
    return ["ip", "netns", "exec", topo.ns(host), *args]


def spawn(host, *args, log=None):
    out = open(log, "w") if log else subprocess.DEVNULL
    return subprocess.Popen(nsx(host, PY, *args), stdout=out, stderr=subprocess.STDOUT,
                            start_new_session=True)


def stop(proc):
    if proc and proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)


def surface():
    services = [(n, ip, port) for n, (ip, _, ports) in topo.HOSTS.items() for port in ports]
    flows = []
    for src, (sip, _, _) in topo.HOSTS.items():
        targets = [s for s in services if s[0] != src]
        out = subprocess.run(nsx(src, PY, str(HERE / "actors.py"), "probe", "--src", sip,
                                 "--targets", json.dumps(targets)),
                             capture_output=True, text=True, check=True).stdout
        for row in json.loads(out):
            flows.append({"src": src, **row})
    return {"possible": len(flows), "reachable": sum(f["reachable"] for f in flows),
            "allowed_flows": [f"{f['src']}→{f['dst']}:{f['port']}" for f in flows if f["reachable"]],
            "flows": flows}


def decode_independent(pcap, tshark):
    """Decodificación de referencia (todas las solicitudes, todas las ADU) para la verdad de terreno."""
    out = subprocess.run([tshark, "-n", "-r", str(pcap), "-Y", "modbus && tcp.dstport == 502",
                          "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
                          "-E", "aggregator=|", "-e", "frame.time_epoch", "-e", "ip.src",
                          "-e", "mbtcp.unit_id", "-e", "modbus.func_code",
                          "-e", "modbus.reference_num", "-e", "modbus.regval_uint16"],
                         capture_output=True, text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        t, src, unit, fc, ref, val = (line.split("\t") + [""] * 6)[:6]
        units, fcs = unit.split("|"), fc.split("|")
        refs = ref.split("|") if ref else []
        for i, f in enumerate(fcs):
            rows.append({"t": float(t), "src": src, "unit": int(units[min(i, len(units) - 1)]),
                         "fc": int(f), "ref": int(refs[i]) if i < len(refs) and refs[i] else None,
                         "values": val, "adus_in_segment": len(fcs)})
    return rows


def run_analyzer(pcap, tshark, sha):
    """Ejecuta la CLI del equipo tal cual, como usuario sin privilegios, y mide su costo."""
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    t0 = time.perf_counter()
    proc = subprocess.run(["runuser", "-u", "ciberfox", "--", PY, "-m", "ciberfox", "analyze-pcap",
                           "--pcap", str(pcap), "--tshark", tshark, "--approved-sha256", sha,
                           *(["--policy", str(POLICY)] if POLICY else [])],
                          cwd=REPO, capture_output=True, text=True)
    wall = time.perf_counter() - t0
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        result = json.loads(proc.stdout) if proc.stdout.strip() else json.loads(proc.stderr)
    except json.JSONDecodeError:
        result = {"raw_stdout": proc.stdout[-2000:], "raw_stderr": proc.stderr[-2000:]}
    return {"exit_code": proc.returncode, "wall_s": wall,
            "cpu_s": (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime),
            "peak_rss_mb_children": after.ru_maxrss / 1024, "result": result}


def detector_microbench(rows):
    det, events = Detector(), []
    for r in rows:
        if r["adus_in_segment"] != 1:
            continue
        value = int(r["values"]) if r["fc"] == 6 and r["values"] and "|" not in r["values"] else None
        events.append(Event(r["t"], r["src"], "192.0.2.20", r["unit"], r["fc"],
                            r["ref"] if r["fc"] == 6 else None, value))
    t0 = time.perf_counter()
    for e in events:
        det.inspect(e)
    dt = time.perf_counter() - t0
    return {"events": len(events), "us_per_event": dt / max(1, len(events)) * 1e6}


def energy_replay(plc_csv, out_csv):
    rows = list(csv.DictReader(open(plc_csv)))
    t0 = float(rows[0]["t_epoch"])
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp_s", "harvest_dc_w", "hot_c", "cold_c", "extra_cooling_w"])
        for r in rows:
            hot, cold = float(r["te_c"]), float(r["ts_c"])
            w.writerow([f"{float(r['t_epoch']) - t0:.3f}",
                        f"{illustrative_teg(hot, cold, 4)['harvest_dc_w']:.6f}", hot, cold, 0.15])
    proc = subprocess.run([PY, "-m", "ciberfox", "replay-power", "--csv", str(out_csv)],
                          cwd=REPO, capture_output=True, text=True)
    return json.loads(proc.stdout or proc.stderr)


ATTACK_FCS = {"A1": {6}, "A2": {6}, "A3": {3}, "A4": {3}, "A6": {16}, "A7": {6}, "A8": {6},
              "A9": {6}, "A10": {3, 6}, "A11": {4, 6}, "R1": {6}, "A5": set()}


def score(truth, rows, alerts, plc_rows, mode):
    out, windows = [], []
    for t in truth:
        lo, hi = t["t_start"] - 0.2, t["t_end"] + 0.6
        windows.append((t["src"], lo, hi))
        fcs = ATTACK_FCS[t["id"]]
        reached = [r for r in rows if r["src"] == t["src"] and lo <= r["t"] <= hi and r["fc"] in fcs]
        if t["id"] == "A6":   # la escritura FC16 del SCADA; sus lecturas normales no cuentan
            reached = [r for r in reached if r["fc"] == 16]
        hits = [a for a in alerts if a["event"]["source"] == t["src"] and lo <= a["event"]["timestamp"] <= hi]
        pump_after = None
        for p in plc_rows:
            if float(p["t_epoch"]) >= t["t_end"] + 1.5:
                pump_after = float(p["pump_cmd"])
                break
        if t["id"] == "A5":
            outcome = "NO DETECTADO (no es tráfico; el detector de red no lo puede ver)"
        elif t["id"] == "R1":
            outcome = "operación legítima"
        elif (t["sent"] or t["errors"]) and not reached:
            outcome = "BLOQUEADO por segmentación"
        elif hits:
            outcome = "DETECTADO (alerta, sin bloqueo)"
        else:
            outcome = "NO DETECTADO"
        if t["id"] in ("A10", "A11") and reached and not hits:
            outcome = "NO DETECTADO (evasión: fila rechazada, solo estado INCOMPLETE)"
        if t["id"] == "A6" and reached and not hits:
            outcome = "NO DETECTADO (FC16: fila rechazada, solo estado INCOMPLETE)"
        out.append({"id": t["id"], "src": t["src"], "desc": t["desc"], "sent": t["sent"],
                    "errors": t["errors"],
                    "answered": t["answered"], "requests_reaching_plc": len(reached),
                    "multi_adu_segments": sum(1 for r in reached if r["adus_in_segment"] > 1),
                    "alert_codes": sorted({a["code"] for a in hits}), "alerts": len(hits),
                    "pump_cmd_after": pump_after, "outcome": outcome})

    def in_attack(src, ts):
        return any(src == s and lo <= ts <= hi for s, lo, hi in windows)
    normal = [r for r in rows if r["src"] in NORMAL_SOURCES and not in_attack(r["src"], r["t"])]
    fps = [a for a in alerts if not in_attack(a["event"]["source"], a["event"]["timestamp"])]
    return out, {"normal_requests": len(normal), "false_positive_alerts": len(fps)}


def plant_summary(plc_rows):
    ti = [float(r["ti_real_c"]) for r in plc_rows]
    above = sum(1 for v in ti if v > 27.0)
    drift = [float(r["ti_reported_c"]) - float(r["ti_real_c"]) for r in plc_rows]
    return {"ti_max_c": max(ti), "ti_min_c": min(ti), "seconds_ti_above_27c": above,
            "max_sensor_lie_k": max(drift), "samples": len(ti)}


def run_mode(mode, out, tshark, sha):
    d = out / mode
    d.mkdir(parents=True)
    os.chmod(d, 0o755)
    procs = []
    print(f"[{mode}] topología", flush=True)
    topo.up(mode)
    try:
        flag = d / "drift.flag"
        plc = spawn("plc", str(HERE / "plc_sim.py"), "--log", str(d / "plant.csv"),
                    "--drift-flag", str(flag), log=d / "plc.log")
        procs.append(plc)
        for name, (ip, _, ports) in topo.HOSTS.items():
            if name != "plc":
                procs.append(spawn(name, str(HERE / "actors.py"), "listen", "--bind",
                                   *[f"{ip}:{p}" for p in ports]))
        time.sleep(2)
        print(f"[{mode}] superficie de ataque", flush=True)
        surf = surface()
        topo.set_maintenance(True)
        surf_maint = surface()["reachable"]
        topo.set_maintenance(False)
        print(f"[{mode}] latencia", flush=True)
        lat = json.loads(subprocess.run(nsx("scada", PY, str(HERE / "actors.py"), "latency", "--n", "2000"),
                                        capture_output=True, text=True, check=True).stdout)
        pcap = d / "captura.pcap"
        cap = subprocess.Popen(nsx("gw", "tcpdump", "-i", "g-plc", "-s", "65535", "-U", "-Z", "root",
                                   "-w", str(pcap), "tcp port 502"),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        time.sleep(1.5)
        before_counters = topo.counters()
        t0 = time.time()
        print(f"[{mode}] escenario de {DURATION} s", flush=True)
        procs.append(spawn("scada", str(HERE / "actors.py"), "scada", "--duration", str(DURATION)))
        procs.append(spawn("hist", str(HERE / "actors.py"), "historian", "--duration", str(DURATION)))
        truth_file = d / "verdad_terreno.jsonl"
        attackers = []
        host_of = {ip: n for n, (ip, _, _) in topo.HOSTS.items()}
        import actors
        for when, aid in SCHEDULE:
            time.sleep(max(0, t0 + when - time.time()))
            src = actors.ATTACKS[aid][0]
            host = host_of.get(src, "plc")
            extra = ["--flag", str(flag), "--hold", "40"] if aid == "A5" else []
            attackers.append(subprocess.Popen(nsx(host, PY, str(HERE / "actors.py"), "attack", aid,
                                                  "--truth", str(truth_file), *extra)))
            print(f"[{mode}]   t={when:>3}s {aid}", flush=True)
        time.sleep(max(0, t0 + DURATION + 2 - time.time()))
        for a in attackers:
            a.wait(60)
        time.sleep(1)
        after_counters = topo.counters()
        stop(cap)
        time.sleep(0.5)
    finally:
        for p in procs:
            stop(p)
        topo.down()
    os.chmod(pcap, 0o644)
    print(f"[{mode}] analizador del equipo", flush=True)
    analyzer = run_analyzer(pcap, tshark, sha)
    rows = decode_independent(pcap, tshark)
    truth = [json.loads(l) for l in open(truth_file)]
    plc_rows = list(csv.DictReader(open(d / "plant.csv")))
    alerts = analyzer["result"].get("alerts", []) if isinstance(analyzer["result"], dict) else []
    attacks, fp = score(truth, rows, alerts, plc_rows, mode)
    deltas = {k: after_counters[k]["packets"] - before_counters.get(k, {"packets": 0})["packets"]
              for k in after_counters}
    result = {
        "label": "DATOS SIMULADOS", "mode": mode, "duration_s": DURATION,
        "surface": {k: v for k, v in surf.items() if k != "flows"},
        "surface_with_maintenance_window": surf_maint,
        "modbus_rtt_ms": lat, "firewall_counters_during_scenario": deltas,
        "pcap_bytes": pcap.stat().st_size,
        "analyzer": {k: v for k, v in analyzer.items() if k != "result"},
        "analyzer_health": analyzer["result"].get("health") if isinstance(analyzer["result"], dict) else None,
        "analyzer_error": analyzer["result"].get("error") if isinstance(analyzer["result"], dict) else analyzer["result"],
        "alerts_total": len(alerts),
        "alert_codes": sorted({a["code"] for a in alerts}),
        "requests_in_capture": len(rows), **fp,
        "detector_microbench": detector_microbench(rows),
        "attacks": attacks, "plant": plant_summary(plc_rows),
        "energy_replay": energy_replay(d / "plant.csv", d / "telemetria_teg.csv"),
    }
    (d / "surface_flows.json").write_text(json.dumps(surf["flows"], indent=1, ensure_ascii=False))
    (d / "analyzer_output.json").write_text(json.dumps(analyzer["result"], indent=1, ensure_ascii=False))
    (d / "resultado.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark", help="Ruta absoluta a TShark 4.6.9+")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--modes", nargs="+", default=["flat", "segmented"])
    ap.add_argument("--policy", type=Path, help="Política JSON que se pasa al analizador del equipo")
    ap.add_argument("--rescore", action="store_true", help="Recalcula la puntuación con artefactos existentes")
    args = ap.parse_args()
    global POLICY
    POLICY = args.policy.resolve() if args.policy else None
    if args.rescore:
        summary = json.loads((args.out / "resumen.json").read_text())
        args.tshark = args.tshark or summary.get("tshark")
        if not args.tshark or not Path(args.tshark).is_file():
            raise SystemExit("--rescore necesita --tshark o la ruta registrada en resumen.json disponible")
        for mode, res in summary["modes"].items():
            d = args.out / mode
            rows = decode_independent(d / "captura.pcap", args.tshark)
            truth = [json.loads(l) for l in open(d / "verdad_terreno.jsonl")]
            plc_rows = list(csv.DictReader(open(d / "plant.csv")))
            alerts = json.loads((d / "analyzer_output.json").read_text()).get("alerts", [])
            res["attacks"], fp = score(truth, rows, alerts, plc_rows, mode)
            res.update(fp)
            (d / "resultado.json").write_text(json.dumps(res, indent=2, ensure_ascii=False))
        (args.out / "resumen.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
        for mode, res in summary["modes"].items():
            for a in res["attacks"]:
                print(mode, a["id"], a["requests_reaching_plc"], a["alert_codes"], a["pump_cmd_after"], a["outcome"])
        return
    if not args.tshark:
        ap.error("--tshark es obligatorio al ejecutar un laboratorio nuevo")
    if os.geteuid() != 0:
        raise SystemExit("El laboratorio necesita root para crear namespaces (el analizador corre sin root)")
    for tool in ("ip", "nft", "tcpdump", "runuser"):
        if not shutil.which(tool):
            raise SystemExit(f"Falta {tool}")
    subprocess.run(["id", "ciberfox"], check=True, capture_output=True)
    args.out.mkdir(parents=True, exist_ok=False)
    os.chmod(args.out, 0o755)
    sha = hashlib.sha256(Path(args.tshark).read_bytes()).hexdigest()
    summary = {"label": "DATOS SIMULADOS", "tshark": args.tshark, "tshark_sha256": sha,
               "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "modes": {}}
    for mode in args.modes:
        summary["modes"][mode] = run_mode(mode, args.out, args.tshark, sha)
    (args.out / "resumen.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(json.dumps({m: {"surface": r["surface"]["reachable"], "alerts": r["alerts_total"],
                          "health": (r["analyzer_health"] or {}).get("status"),
                          "error": r["analyzer_error"]} for m, r in summary["modes"].items()},
                     indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
