"""Fixtures sintéticos escritos a disco. Nunca abre sockets."""
from dataclasses import asdict
import html
import json
from pathlib import Path
import socket
import struct

from .detector import Detector, Event
from .energy import EnergyManager, PowerSample, illustrative_teg, summarize


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
    return '''<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'">
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
