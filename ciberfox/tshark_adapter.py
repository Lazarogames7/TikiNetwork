"""Adaptador OFFLINE. No copia código Wireshark ni usa sus APIs internas.

Solo PCAP clásico Ethernet IPv4, solicitudes Modbus/TCP puerto 502.
La cobertura intencionadamente limitada se devuelve como dato, no se oculta.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile
from .detector import Event

FIELDS = ("frame.time_epoch", "ip.src", "ip.dst", "mbtcp.unit_id",
          "modbus.func_code", "modbus.reference_num", "modbus.regval_uint16")
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
    match = re.search(r"TShark \(Wireshark\) (\d+)\.(\d+)\.(\d+)([^\s]*)", text)
    if not match:
        raise ValueError("No se pudo verificar versión de TShark")
    major, minor, patch = map(int, match.groups()[:3])
    suffix = match.group(4)
    if (major, minor) != (4, 6) or patch < 9 or suffix:
        raise ValueError("Política revisada 2026-10-22: rama estable 4.6, parche >=9; revisar antes de ampliar")
    return f"{major}.{minor}.{patch}{suffix}"


def parse_row(line: str) -> Event:
    values = line.rstrip("\r\n").split("\t")
    if len(values) != len(FIELDS) or any("," in value for value in values):
        raise ValueError("Fila ambigua/múltiples PDU: no se descartan valores silenciosamente")
    timestamp, source, destination, unit, function, address, value = values
    event = Event(float(timestamp), source, destination, int(unit), int(function),
                  int(address) if address else None, int(value) if value else None)
    event.validate()
    return event


def command(binary: str, pcap: str) -> list[str]:
    args = [binary, "-n", "--only-protocols", PROTOCOLS,
            "-r", pcap, "-Y", "modbus && tcp.dstport == 502",
            "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a",
            "-E", "aggregator=,"]
    for field in FIELDS:
        args.extend(["-e", field])
    return args


def decode(pcap: Path, binary: Path, approved_sha256: str) -> tuple[list[Event], dict]:
    if os.name != "posix" or os.geteuid() == 0:
        raise ValueError("Adaptador requiere POSIX y usuario sin privilegios root")
    if not binary.is_absolute() or not binary.is_file():
        raise ValueError("Ruta absoluta a TShark requerida")
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
        del snapshot
        packets = validate_pcap(local_pcap)
        for name in ("config", "plugins", "extcap"):
            (sandbox_dir / name).mkdir()
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
               "WIRESHARK_CONFIG_DIR": str(sandbox_dir / "config"),
               "WIRESHARK_PLUGIN_DIR": str(sandbox_dir / "plugins"),
               "WIRESHARK_EXTCAP_DIR": str(sandbox_dir / "extcap")}
        launcher = str(Path(__file__).with_name("limited_exec.py"))

        def run(args):
            with (sandbox_dir / "stdout").open("wb") as out, (sandbox_dir / "stderr").open("wb") as err:
                result = subprocess.run([sys.executable, "-I", launcher, *args],
                                        stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                        cwd=sandbox_dir, env=env, timeout=25, check=False)
            if result.returncode:
                # Do not echo untrusted parser diagnostics into terminal.
                raise ValueError(f"TShark falló ({result.returncode}); análisis incompleto")
            return sandbox_dir / "stdout"

        version = check_version(run([str(binary), "--version"]).read_text()[:8192])
        rows = run(command(str(binary), str(local_pcap)))
        events, rejected = [], 0
        with rows.open(encoding="utf-8", errors="strict") as stream:
            for _ in range(MAX_RECORDS + 1):
                line = stream.readline(8193)
                if not line:
                    break
                if len(line) > 8192 or len(events) + rejected >= MAX_RECORDS:
                    raise ValueError("Salida de TShark excede límites")
                try:
                    events.append(parse_row(line))
                except ValueError:
                    rejected += 1
        return events, {"tshark_version": version, "binary_sha256": actual_hash,
                        "packets_in_file": packets, "parsed_requests": len(events),
                        "rejected_rows": rejected,
                        "status": "INCOMPLETE" if rejected or not events else "SCOPED_ANALYSIS",
                        "scope": "IPv4 Modbus/TCP destination 502; FC06 values only; offline",
                        "production_ready": False}
