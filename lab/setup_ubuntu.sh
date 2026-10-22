#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ciberfox contributors
# Prepara Ubuntu 24.04 para el laboratorio (probado tal cual el 22-oct-2026).
# Necesita root e internet SOLO para instalar. El laboratorio en sí corre sin red.
set -euo pipefail

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  python3 iproute2 nftables tcpdump ethtool util-linux \
  cmake ninja-build pkg-config flex bison libglib2.0-dev libgcrypt20-dev \
  libc-ares-dev libpcre2-dev zlib1g-dev libpcap-dev libspeexdsp-dev libxml2-dev xz-utils curl

# Usuario sin privilegios: el adaptador del equipo se niega a correr como root.
id ciberfox >/dev/null 2>&1 || useradd -m -s /bin/bash ciberfox

# TShark 4.6.9 desde la fuente oficial (los paquetes de Ubuntu/PPA traen 4.2.2/4.6.6,
# que la política de versión del adaptador rechaza correctamente). ~15 min con 2 núcleos.
if [ ! -x /opt/tshark-4.6.9/bin/tshark ]; then
  mkdir -p /opt/ws && cd /opt/ws
  curl --fail --location --proto '=https' --tlsv1.2 --remote-name \
    https://2.na.dl.wireshark.org/src/all-versions/wireshark-4.6.9.tar.xz
  echo "d062d416a1ab3a49975aafe3a671c882dde0562ccd71b078808ceb59d465fc0f  wireshark-4.6.9.tar.xz" | sha256sum -c -
  tar xf wireshark-4.6.9.tar.xz && mkdir -p build && cd build
  OFF=""; for t in wireshark stratoshark logray sharkd rawshark editcap mergecap reordercap text2pcap \
      randpkt dftest capinfos captype tfshark sshdump ciscodump udpdump androiddump randpktdump wifidump etwdump; do
    OFF="$OFF -DBUILD_$t=OFF"; done
  cmake -G Ninja ../wireshark-4.6.9 $OFF -DENABLE_LUA=OFF -DENABLE_PLUGINS=OFF \
    -DCMAKE_INSTALL_PREFIX=/opt/tshark-4.6.9 -DCMAKE_BUILD_TYPE=Release >/dev/null
  ninja tshark && ninja install >/dev/null
fi
/opt/tshark-4.6.9/bin/tshark --version | head -1
echo "Listo. Ejecuta: sudo python3 lab/run_lab.py --tshark /opt/tshark-4.6.9/bin/tshark --out lab_result"
