# Ciberfox Thermal OT

Prototipo defensivo y offline para un hackatón: correlaciona eventos OT/SCADA simulados con métricas de agua y energía, y evalúa si un monitor de bajo consumo podría alimentarse parcialmente con recuperación termoeléctrica del calor residual.

> **DATOS SIMULADOS.** Este repositorio no contiene telemetría de empresas, credenciales ni conexiones a PLC reales. No es un producto certificado ni debe controlar procesos industriales.

## Qué incluye

- `ciberfox/`: simulador energético, reglas Modbus/TCP y adaptador offline para TShark.
- `tests/`: 22 pruebas unitarias de contabilidad, detección y validación de entradas.
- `demo_result/`: PCAP y panel local generados con direcciones reservadas para documentación.
- `docs/PROPUESTA.md`: arquitectura, competencia, sostenibilidad y límites.
- `docs/AUDITORIA_SEGURIDAD.md`: hallazgos conocidos; las correcciones siguen en desarrollo.
- `docs/hackathon/`: entregables para Mérida, CSV oficial simulado y cálculo reproducible de PUE, WUE y balance hídrico.

## Inicio rápido

Requiere Python 3.11 o posterior. La demo y las pruebas usan solo la biblioteca estándar.

```bash
python3 -m unittest discover -s tests -v
python3 -m ciberfox demo --out nueva_demo
python3 docs/hackathon/calcular.py
```

El último comando reproduce las métricas del kit y actualiza `docs/hackathon/resultados.json`. No conecta redes ni ejecuta TShark.

## Resultado del escenario del hackatón

Sobre 504 filas simuladas del kit:

- PUE agregado ilustrativo: **1.273416**.
- WUE de captación ilustrativo: **0.382222 L/kWh IT**.
- Escenario central: **546.04 L netos de captación potencialmente evitada** si una intervención elimina el 50 % del exceso estimado después de la primera hora.

El ahorro es contrafactual y no una medición de campo. La propuesta TEG tampoco tiene todavía un crédito energético o de carbono: requiere una prueba física con balance completo.

## Estado de seguridad

El analizador es pasivo y nunca envía comandos ni bloquea equipos. La auditoría identifica como pendientes el aislamiento real de TShark, cobertura de protocolos, configuración por instalación, autenticación, autorización, trazabilidad y validación con TShark mantenido. Una prueba sintética exitosa no equivale a declarar una red segura.

## Licencias

El CSV y la documentación copiada del CIFOX Starter Kit conservan su licencia MIT en `docs/hackathon/LICENSE_KIT.txt`. Wireshark/TShark no se redistribuyen. El equipo aún debe elegir una licencia para el código original antes de hacer público este repositorio.

