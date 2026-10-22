# Procedencia de la simulación actualizada

- Archivo recibido: `ciberfox-revision2-simulacion.zip`
- SHA-256: `bfc3522dd72a91fb3544252fc45acda14377eddb1b22fe14b69a2ef1e0407834`
- Fecha de integración: 2026-10-22
- Contenedor: 37 entradas y 943,345 bytes sin comprimir.
- Validación previa: sin rutas absolutas, componentes `..`, enlaces simbólicos ni patrones de credenciales.

Solo se integraron `lab_result/` y su reporte. Las copias de `ciberfox.py` y `lab/` del ZIP eran anteriores al endurecimiento existente en `main`; reemplazarlas habría eliminado encabezados SPDX, la descarga HTTPS reforzada, la ejecución sin `shell=True`, la interfaz corregida de `--rescore` y la prueba portable de GitHub Actions.

Se verificó que:

- Los SHA-256 de ambos PCAP coinciden con `analyzer_health.pcap_sha256`.
- Los PCAP cumplen la estructura y el número de paquetes declarado.
- El SHA-256 de `lab/politica_lab.json` coincide con cada análisis.
- Cada `resultado.json` coincide con su modo dentro de `resumen.json`.
- Cada `analyzer_output.json` coincide con la salud registrada.
- Cada escenario contiene 12 eventos únicos de verdad de terreno.
