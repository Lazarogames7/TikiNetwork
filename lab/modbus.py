# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ciberfox contributors
"""Modbus/TCP mínimo (solo biblioteca estándar) para el laboratorio. DATOS SIMULADOS.

Solo se usa dentro de namespaces de red aislados del laboratorio, con
direcciones de documentación 192.0.2.0/24. Nunca debe apuntarse a equipos reales.
"""
import socket
import struct
import threading


class ModbusError(Exception):
    pass


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("conexión cerrada")
        data += chunk
    return data


class Client:
    """Cliente Modbus/TCP con conexión persistente (como un SCADA real)."""

    def __init__(self, host, port=502, source=None, timeout=2.0):
        self.sock = socket.create_connection((host, port), timeout=timeout,
                                             source_address=(source, 0) if source else None)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.tid = 0
        self.lock = threading.Lock()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def request(self, unit, pdu):
        with self.lock:
            self.tid = (self.tid + 1) & 0xFFFF
            self.sock.sendall(struct.pack("!HHHB", self.tid, 0, len(pdu) + 1, unit) + pdu)
            tid, _, length, _ = struct.unpack("!HHHB", _recv_exact(self.sock, 7))
            body = _recv_exact(self.sock, length - 1)
        if body[0] & 0x80:
            raise ModbusError(f"excepción Modbus {body[1]}")
        return body

    def read_holding(self, address, count=1, unit=1):
        body = self.request(unit, struct.pack("!BHH", 3, address, count))
        return list(struct.unpack(f"!{body[1] // 2}H", body[2:]))

    def read_input(self, address, count=1, unit=1):
        body = self.request(unit, struct.pack("!BHH", 4, address, count))
        return list(struct.unpack(f"!{body[1] // 2}H", body[2:]))

    def write_register(self, address, value, unit=1):          # FC06
        return self.request(unit, struct.pack("!BHH", 6, address, value))

    def write_registers(self, address, values, unit=1):        # FC16
        pdu = struct.pack("!BHHB", 16, address, len(values), 2 * len(values))
        pdu += struct.pack(f"!{len(values)}H", *values)
        return self.request(unit, pdu)

    def write_coil(self, address, on, unit=1):                 # FC05
        return self.request(unit, struct.pack("!BHH", 5, address, 0xFF00 if on else 0))


class Server:
    """Servidor Modbus/TCP con hilos. `on_write(address, value)` se llama por cada registro escrito."""

    def __init__(self, host, port, holding, inputs, unit=1, on_write=None):
        self.holding, self.inputs, self.unit = holding, inputs, unit
        self.on_write = on_write or (lambda a, v: None)
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(64)
        self.requests = 0

    def serve_forever(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with conn:
            while True:
                try:
                    tid, proto, length, unit = struct.unpack("!HHHB", _recv_exact(conn, 7))
                    pdu = _recv_exact(conn, length - 1)
                except (ConnectionError, OSError, struct.error):
                    return
                self.requests += 1
                reply = self._process(unit, pdu)
                try:
                    conn.sendall(struct.pack("!HHHB", tid, proto, len(reply) + 1, unit) + reply)
                except OSError:
                    return

    def _process(self, unit, pdu):
        fc = pdu[0]
        exc = lambda code: bytes([fc | 0x80, code])
        if unit != self.unit:
            return exc(11)                                     # gateway target failed
        try:
            with self.lock:
                if fc in (3, 4):
                    addr, count = struct.unpack("!HH", pdu[1:5])
                    table = self.holding if fc == 3 else self.inputs
                    if not 1 <= count <= 125 or any(a not in table for a in range(addr, addr + count)):
                        return exc(2)
                    values = [table[a] for a in range(addr, addr + count)]
                    return bytes([fc, 2 * count]) + struct.pack(f"!{count}H", *values)
                if fc == 6:
                    addr, value = struct.unpack("!HH", pdu[1:5])
                    if addr not in self.holding:
                        return exc(2)
                    self.holding[addr] = value
                    self.on_write(addr, value)
                    return pdu[:5]
                if fc == 16:
                    addr, count, _ = struct.unpack("!HHB", pdu[1:6])
                    values = struct.unpack(f"!{count}H", pdu[6:6 + 2 * count])
                    if any(a not in self.holding for a in range(addr, addr + count)):
                        return exc(2)
                    for offset, value in enumerate(values):
                        self.holding[addr + offset] = value
                        self.on_write(addr + offset, value)
                    return pdu[:5]
                if fc == 5:
                    return pdu[:5]                             # bobina aceptada, sin efecto físico
        except struct.error:
            return exc(3)
        return exc(1)
