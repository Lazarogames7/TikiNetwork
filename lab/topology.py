# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ciberfox contributors
"""Topología de laboratorio con namespaces de red Linux. DATOS SIMULADOS.

Un namespace por host + un gateway. Cada host tiene una /32 y su única ruta va
al gateway, así que TODO el tráfico entre hosts (incluso dentro de la misma zona)
atraviesa el filtro nftables: microsegmentación por host, no solo por zona.

  Zona A · Campo    plc     192.0.2.20   Modbus/TCP 502
  Zona B · Control  scada   192.0.2.10   HMI 8080
                    hist    192.0.2.11   HTTPS 443 (simulado)
                    eng     192.0.2.12   SSH 22 (simulado)
  Zona C · DMZ      mon     192.0.2.34   HTTPS 443 (tablero)
  Zona D · IT       laptop  192.0.2.99   SMB 445 (simulado)

Requiere Linux con root (o un contenedor --privileged). Nada sale del host:
los namespaces no tienen ruta hacia la red real.
"""
import subprocess
from pathlib import Path

HOSTS = {  # nombre: (ip, zona, servicios)
    "plc": ("192.0.2.20", "A", [502]),
    "scada": ("192.0.2.10", "B", [8080]),
    "hist": ("192.0.2.11", "B", [443]),
    "eng": ("192.0.2.12", "B", [22]),
    "mon": ("192.0.2.34", "C", [443]),
    "laptop": ("192.0.2.99", "D", [445]),
}
GW, GW_LINK = "cf-gw", "169.254.0.1"
HERE = Path(__file__).resolve().parent


def sh(cmd, check=True):
    """Ejecuta argumentos fijos sin intérprete de comandos."""
    return subprocess.run(cmd, shell=False, check=check, capture_output=True, text=True)


def ns(name):
    return f"cf-{name}"


def down():
    for name in list(HOSTS) + ["gw"]:
        sh(["ip", "netns", "del", f"cf-{name}"], check=False)


def up(mode):
    assert mode in ("flat", "segmented")
    down()
    sh(["ip", "netns", "add", GW])
    sh(["ip", "netns", "exec", GW, "ip", "link", "set", "lo", "up"])
    sh(["ip", "netns", "exec", GW, "sysctl", "-qw", "net.ipv4.ip_forward=1"])
    sh(["ip", "netns", "exec", GW, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0"])
    for name, (ip, _, _) in HOSTS.items():
        n, gif = ns(name), f"g-{name}"
        sh(["ip", "netns", "add", n])
        sh(["ip", "netns", "exec", n, "ip", "link", "set", "lo", "up"])
        sh(["ip", "link", "add", "h0", "netns", n, "type", "veth", "peer", "name", gif, "netns", GW])
        sh(["ip", "netns", "exec", n, "ip", "addr", "add", f"{ip}/32", "dev", "h0"])
        sh(["ip", "netns", "exec", n, "ip", "link", "set", "h0", "up"])
        sh(["ip", "netns", "exec", n, "ip", "route", "add", GW_LINK, "dev", "h0"])
        sh(["ip", "netns", "exec", n, "ip", "route", "add", "default", "via", GW_LINK, "dev", "h0", "onlink"])
        sh(["ip", "netns", "exec", GW, "ip", "addr", "add", f"{GW_LINK}/32", "dev", gif])
        sh(["ip", "netns", "exec", GW, "ip", "link", "set", gif, "up"])
        sh(["ip", "netns", "exec", GW, "sysctl", "-qw", f"net.ipv4.conf.{gif}.rp_filter=0"])
        sh(["ip", "netns", "exec", GW, "ip", "route", "add", f"{ip}/32", "dev", gif])
        # Sin offloads: los paquetes capturados tienen el tamaño real del cable.
        for target, interface in ((n, "h0"), (GW, gif)):
            sh(["ip", "netns", "exec", target, "ethtool", "-K", interface,
                "tso", "off", "gso", "off", "gro", "off", "tx", "off", "rx", "off"], check=False)
    rules = HERE / ("nft_segmented.nft" if mode == "segmented" else "nft_flat.nft")
    sh(["ip", "netns", "exec", GW, "nft", "-f", str(rules)])


def set_maintenance(on):
    verb = "add" if on else "delete"
    sh(["ip", "netns", "exec", GW, "nft", verb, "element", "inet", "ciberfox",
        "maintenance", "{", "192.0.2.12", "}"], check=False)


def counters():
    import json
    out = sh(["ip", "netns", "exec", GW, "nft", "-j", "list", "counters"]).stdout
    result = {}
    for item in json.loads(out)["nftables"]:
        if "counter" in item:
            c = item["counter"]
            result[c["name"]] = {"packets": c["packets"], "bytes": c["bytes"]}
    return result


if __name__ == "__main__":
    import sys
    if sys.argv[1] == "down":
        down()
    else:
        up(sys.argv[1])
