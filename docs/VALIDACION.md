# Validación

## Revisión local de integración

Ejecutada el 22 de octubre de 2026 con Python 3.14.5 en macOS:

- `python3 -m py_compile ciberfox.py lab/*.py`: correcto.
- `python3 ciberfox.py test`: 42 pruebas, 39 aprobadas y 3 omitidas por requerir Linux/seccomp/Landlock.
- `python3 ciberfox.py demo --out demo_result`: correcto.
- `python3 docs/hackathon/calcular.py`: correcto y determinista.

La prueba de integración usa un doble de TShark declarado expresamente. Comprueba orquestación, hash, validación y manejo de campos; no sustituye una disección real.

## Evidencia Linux recibida

`lab_result/` conserva una corrida simulada generada el 22 de octubre de 2026 a las 14:42 en Ubuntu 24.04 con Python 3.13 y TShark 4.6.9 real. El reporte de remediación indica 42/42 pruebas aprobadas en ese entorno. Durante esta integración se verificaron los hashes de ambos PCAP, su estructura, la política, la correspondencia entre resumen, resultados y salida del analizador, y las 12 entradas de verdad de terreno. No se repitió el laboratorio completo de 8 minutos porque requiere namespaces y nftables con root.

Los artefactos reportan la versión y SHA-256 del binario, SHA-256 del PCAP, capas del sandbox, latencia, superficie de red, alertas, falsos positivos y balance energético. El estado `INCOMPLETE` es correcto: dos filas con múltiples ADU quedan registradas como no inspeccionadas.

## Alcance

No se validaron hardware TEG, medición física de potencia, huella incorporada, integración I2C/serial, tráfico de una empresa, protocolos distintos de Modbus/TCP ni eficacia de campo. No se afirma certificación industrial ni carbono neto cero.
