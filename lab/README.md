**Laboratorio de simulación OT — Ciberfox.** DATOS SIMULADOS. Red aislada en namespaces Linux, direcciones de documentación 192.0.2.0/24, sin conexión a ninguna red real.

Prueba el código del equipo **sin modificarlo**: el analizador se ejecuta igual que en el README principal (`python3 -m ciberfox analyze-pcap` con TShark real, como usuario sin root), sobre tráfico Modbus generado en vivo por una planta simulada.

**Qué monta**

```
            Zona B · Control           Zona C · DMZ        Zona D · IT
         scada .10  hist .11  eng .12     mon .34          laptop .99
              \        |        /            |                 |
               +-------+-------+------ GATEWAY (nftables) ------+
                               |   ← captura tcpdump (TAP)
                            plc .20   Zona A · Campo  (Modbus/TCP 502 + planta térmica)
```

Cada host tiene su propio namespace con una /32 y su única ruta va al gateway, así que todo flujo entre hosts —incluso dentro de la misma zona— pasa por el filtro: es microsegmentación por host, no solo por zona.

| Archivo | Qué hace |
|---|---|
| `topology.py` | Crea/destruye namespaces, veth y rutas; carga las reglas. |
| `nft_flat.nft` / `nft_segmented.nft` | Red plana (línea base) / lista blanca Zero Trust. |
| `modbus.py` | Cliente y servidor Modbus/TCP mínimos, solo biblioteca estándar. |
| `plc_sim.py` | PLC virtual con modelo térmico de primer orden (bomba → temperatura de entrada a servidores). |
| `actors.py` | SCADA, historian, servicios ficticios, sondeo de superficie, latencia y 11 ataques. |
| `run_lab.py` | Orquesta todo, ejecuta el analizador del equipo y lo puntúa contra la verdad de terreno. |
| `setup_ubuntu.sh` | Instala dependencias y compila TShark 4.6.9 verificado por SHA256. |

**Cómo correrlo** (Ubuntu 24.04 con root; probado así):

```bash
sudo bash lab/setup_ubuntu.sh            # una vez, con internet (~15 min por la compilación)
sudo python3 lab/run_lab.py --tshark /opt/tshark-4.6.9/bin/tshark --out lab_result
```

Dura unos 8 minutos (dos escenarios de 200 s más mediciones). La carpeta de salida debe ser nueva. `--modes segmented` corre solo uno. `--rescore` recalcula la puntuación sobre una salida existente y necesita el mismo TShark disponible; puede indicarlo con `--tshark` o usar la ruta guardada en `resumen.json`.

En macOS no hay namespaces de red: usa una VM Ubuntu (UTM, Multipass) o un contenedor Linux con `--privileged`. **La vía contenedor no se probó**; la VM con Ubuntu 24.04 replica exactamente el entorno donde sí se probó.

**Calendario de ataques** (igual en ambos modos)

| t (s) | ID | Origen | Qué hace |
|---:|---|---|---|
| 15 | A1 | laptop IT | FC06 consigna 100 = 50 |
| 25 | A4 | laptop IT | Reconocimiento: registros 0–250 y unit IDs 1–10 |
| 40 | A3 | laptop IT | Inundación: 2000 lecturas FC03 |
| 55 | A7 | SCADA comprometido | FC06 a registro no aprobado 200 |
| 62 | A6 | SCADA comprometido | FC16 a 100–101 = [40, 300] |
| 70 | A8 | historian | FC06 (es un equipo de solo lectura) |
| 78 | A9 | estación de ingeniería | FC06 fuera de ventana de mantenimiento |
| 86 | A10 | laptop IT | FC03 + FC06 = 55 en un mismo segmento TCP |
| 94 | A11 | historian | FC04 + FC06 = 60 en un mismo segmento TCP |
| 105 | A2 | SCADA comprometido | Consigna de bomba a 5 % («apagar la bomba») |
| 140 | R1 | operador | Restablece 40 % tras revisar la alerta (35 s de respuesta humana) |
| 150 | A5 | sensor | Deriva: la temperatura reportada sube 0.08 K/s durante 40 s |

**Límites del laboratorio.** La planta es un modelo didáctico, no validado contra una instalación real. Las latencias son de veth dentro de un solo kernel, no de un switch industrial. Hay un solo PLC porque la política del `Detector` tiene un único destino codificado. El historian «HTTPS» y otros servicios son escuchas TCP ficticias. La energía TEG sale de `illustrative_teg` del propio equipo con la temperatura simulada del aire de escape; no es una medición.
