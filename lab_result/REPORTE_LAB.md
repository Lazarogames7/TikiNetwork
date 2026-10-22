# Resultados del laboratorio Ciberfox — revisión 2

**DATOS SIMULADOS.** Corrida generada el 2026-10-22 14:42:44 con `ciberfox.py` revisión 2 y `lab/politica_lab.json`. TShark 4.6.9 compilado desde la fuente oficial sin modificar; binario `567f46b2…ed1d`. Este reporte sustituye al de la primera ronda.

## 1. Qué se probó

Una planta simulada de 6 equipos (PLC, SCADA, historian, ingeniería, monitor y laptop de IT), cada uno en su propio namespace de red y con todo el tráfico pasando por un gateway con nftables. El PLC habla Modbus/TCP y tiene un modelo térmico (bomba → temperatura de entrada). El mismo escenario de 200 s se corrió dos veces: red plana y red microsegmentada. En ambas hubo 434 solicitudes legítimas y los mismos eventos programados. La captura la analizó la CLI del equipo, con TShark real, sin root y con el sandbox obligatorio, y se calificó contra la verdad de terreno.

## 2. Cifras medidas

| Métrica | Red plana | Microsegmentada |
|---|---:|---:|
| Flujos alcanzables (sondeo TCP real) | 30 / 30 | **4 / 30 (−86.7 %)**; 5 con ventana de mantenimiento |
| RTT Modbus SCADA→PLC, mediana / p99 (2000 lecturas) | 0.056 / 0.103 ms | 0.053 / 0.086 ms |
| Paquetes en la captura | 5518 | 1393 |
| Solicitudes Modbus interpretadas / filas no separables | 2486 / 2 | 447 / 1 |
| Alertas totales | 28 | 4 |
| Falsas alarmas sobre tráfico normal | 0 de 434 | 0 de 434 |
| Analizador completo: tiempo / CPU / RSS pico | 1.50 s / 1.01 s / 154 MB | 1.07 s / 0.87 s / 154 MB |
| Regla de detección pura | 5.3 µs/evento | 6.3 µs/evento |
| Estado del análisis | `INCOMPLETE` | `INCOMPLETE` |
| Sandbox completo para la plataforma | True | True |

El estado `INCOMPLETE` es intencional: hubo segmentos con varias ADU que no se pueden separar, y el analizador lo declara en vez de reportar «todo limpio». Las latencias son de veth en un solo kernel: muestran que el filtro no añade un retraso relevante, no la latencia de una red industrial.

## 3. Ataque por ataque

| ID | Ataque | Red plana | Microsegmentada |
|---|---|---|---|
| A1 | Laptop de IT escribe la consigna de la bomba (FC06) | Detectado `UNAUTHORIZED_COMMAND`; consigna después: 50 % | **Bloqueado** (0 solicitudes llegaron al PLC) |
| A4 | Reconocimiento: barrido de registros y unit IDs | Detectado `UNAUTHORIZED_READ`, `UNEXPECTED_ASSET` | **Bloqueado** (0 solicitudes llegaron al PLC) |
| A3 | Inundación de 2000 lecturas | Detectado `READ_FLOOD` | **Bloqueado** (0 solicitudes llegaron al PLC) |
| A8 | Historian (solo lectura) escribe | Detectado `UNAUTHORIZED_COMMAND`; consigna después: 40 % | **Bloqueado** (0 solicitudes llegaron al PLC) |
| A9 | Ingeniería escribe fuera de ventana de mantenimiento | Detectado `UNAUTHORIZED_COMMAND`; consigna después: 45 % | **Bloqueado** (0 solicitudes llegaron al PLC) |
| A10 | Laptop esconde FC06 detrás de una lectura (mismo segmento) | Detectado `UNINSPECTED_CONTROL`; consigna después: 55 % | **Bloqueado** (0 solicitudes llegaron al PLC) |
| A11 | Historian esconde FC06 detrás de una lectura (mismo segmento) | Detectado `UNINSPECTED_CONTROL`; consigna después: 60 % | Detectado `UNINSPECTED_CONTROL`; consigna después: 60 % |
| A7 | SCADA comprometido escribe registro no aprobado (200) | Detectado `UNAPPROVED_REGISTER` | Detectado `UNAPPROVED_REGISTER` |
| A6 | SCADA comprometido escribe [40, 300] con FC16 | Detectado `PROCESS_LIMIT`; consigna después: 40 % | Detectado `PROCESS_LIMIT`; consigna después: 40 % |
| A2 | SCADA comprometido apaga la bomba (consigna 5 %) | Detectado `PROCESS_LIMIT`; consigna después: 5 % | Detectado `PROCESS_LIMIT`; consigna después: 5 % |
| A5 | Sensor reporta temperatura falsa (deriva +3.2 K) | **No detectado** | **No detectado** |

**Resumen.** Red plana: 10 de 10 ataques de red detectados y 0 bloqueados. Microsegmentada: **6 bloqueados** (A1, A4, A3, A8, A9, A10) y **4 detectados** (A7, A6, A11, A2). A5 no es tráfico de red y ningún modo lo ve. R1 (el operador restablece la consigna) no generó alerta en ninguno.

## 4. Qué significa

1. **La segmentación previene y el detector vigila.** En la red plana el detector avisa, pero los cambios ya ocurrieron en el PLC (por ejemplo A1, A10, A11 y A2). Con segmentación, la mayoría de los ataques desde equipos que no deben escribir ni siquiera llegan.
2. **Un SCADA comprometido pasa cualquier lista blanca de red** (A2, A6, A7): tiene permiso de hablar con el PLC. Solo la inspección del contenido (`PROCESS_LIMIT`, `UNAPPROVED_REGISTER`) lo distingue.
3. **A11 atraviesa el firewall.** El filtro por código de función solo lee la primera ADU del segmento, así que la escritura pegada detrás pasa y la consigna llegó a 60 %. El detector la marca con `UNINSPECTED_CONTROL`, pero no la frena. Esto justifica una guardia de comandos que reensamble y valide cada ADU (Solución 3).
4. **A5 queda fuera del alcance de un detector de red.** Hace falta un módulo estadístico sobre los valores del proceso.
5. **Efecto físico simulado de A2** (35 s de respuesta humana): la temperatura de entrada llegó a 27.8 °C (plana) y 28.2 °C (segmentada), y estuvo 22 s y 30 s por encima de 27 °C (referencia didáctica de ASHRAE).

## 5. Diferencias con la primera ronda

| Dato | Primera ronda (código original del equipo) | Revisión 2 |
|---|---|---|
| Ataques de red detectados en red plana | 6 de 10 | 10 de 10 |
| A6 (FC16) | No detectado (fila rechazada) | Detectado `PROCESS_LIMIT`; consigna después: 40 % |
| A10 y A11 (escritura escondida) | Sin alerta, solo `INCOMPLETE` global | `UNINSPECTED_CONTROL` por flujo |
| A3 (inundación) | Sin alerta | `READ_FLOOD` (una sola alerta escalada) |
| Alertas en red plana | 14 | 28 (nuevas alertas de lectura no autorizada, agrupadas cada 60 s, y de escritura no inspeccionada) |

## 6. Límites

Todo es simulado: no hay PLC físico ni red industrial. Un solo PLC. La identidad del origen es la dirección IP. No se inspecciona tráfico cifrado (puerto 802): se cuenta y marca el análisis como incompleto. El laboratorio completo no se probó en macOS. Las mediciones físicas de energía siguen pendientes. El código propio se publica bajo MIT y TShark conserva su licencia GPL-2.0-or-later como herramienta externa.

## 7. Archivos

`resumen.json` (todo) y, por modo (`flat/`, `segmented/`): `captura.pcap`, `analyzer_output.json`, `verdad_terreno.jsonl`, `plant.csv`, `telemetria_teg.csv`, `surface_flows.json` y `resultado.json`.
