# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ciberfox contributors
"""PLC virtual + planta de enfriamiento simplificada. DATOS SIMULADOS.

Modelo de primer orden (didáctico, NO validado contra una instalación):
  C·dTi/dt = Q − UA(bomba)·(Ti − Ts)      Ti: temperatura de entrada a servidores
  UA = UA_nom·(bomba_real/40)^0.8        bomba al 40 % → Ti ≈ 24 °C en régimen
Registros:
  holding 100  consigna de bomba (%)       ← el único que el Detector permite (20–60)
  holding 101  setpoint agua fría (°C×10)
  holding 200  modo mantenimiento (0/1)
  holding 0–9  configuración genérica (objetivo de reconocimiento)
  input 0..4   Ti, Tr (retorno), caudal, Ts (suministro), Te (aire de escape)  ×10
El ataque de deriva de sensor (A5) se activa con un archivo bandera: simula un
transmisor comprometido, NO es visible como tráfico de red.
"""
import argparse
import csv
import random
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from modbus import Server  # noqa: E402

Q_KW, C_KJ_K, UA_NOM, TS_C = 40.0, 200.0, 40.0 / 12.0, 12.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.0.2.20")
    ap.add_argument("--log", type=Path, required=True)
    ap.add_argument("--drift-flag", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    holding = {a: 0 for a in range(10)}
    holding.update({100: 40, 101: 120, 200: 0})
    inputs = {a: 0 for a in range(5)}
    state = {"pump": 40.0, "ti": 24.0, "drift": 0.0}

    server = Server(args.host, 502, holding, inputs)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    with args.log.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t_epoch", "pump_cmd", "pump_real", "ti_real_c", "ti_reported_c",
                    "tr_c", "te_c", "ts_c", "flow_ls", "drift_active", "requests"])
        next_tick = time.time()
        while True:
            next_tick += 1.0
            with server.lock:
                cmd = max(0.0, min(100.0, float(holding[100])))
            # actuador: rampa máxima 10 %/s
            state["pump"] += max(-10.0, min(10.0, cmd - state["pump"]))
            pump = max(state["pump"], 0.0)
            ua = UA_NOM * (pump / 40.0) ** 0.8 if pump > 0 else 0.0
            q = Q_KW * (1 + rng.uniform(-0.01, 0.01))
            ts = TS_C + rng.uniform(-0.05, 0.05)
            state["ti"] += (q - ua * (state["ti"] - ts)) / C_KJ_K
            flow = 2.0 * pump / 40.0
            tr = ts + (q / (flow * 4.186) if flow > 0.05 else 25.0)
            te = state["ti"] + 15.0
            drifting = args.drift_flag.exists()
            state["drift"] = state["drift"] + 0.08 if drifting else 0.0
            ti_rep = state["ti"] + state["drift"]
            with server.lock:
                for i, v in enumerate((ti_rep, tr, flow, ts, te)):
                    inputs[i] = max(0, min(65535, int(round(v * 10))))
            w.writerow([f"{time.time():.3f}", cmd, round(pump, 2), round(state["ti"], 3),
                        round(ti_rep, 3), round(tr, 3), round(te, 3), round(ts, 3),
                        round(flow, 3), int(drifting), server.requests])
            f.flush()
            time.sleep(max(0.0, next_tick - time.time()))


if __name__ == "__main__":
    main()
