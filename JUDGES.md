# Guía para jueces

## Revisión en cinco minutos

```bash
python3 ciberfox.py test
python3 ciberfox.py demo --out revision_juez
python3 docs/hackathon/calcular.py
```

1. Confirme `Ran 42 tests` y `OK`. En macOS habrá 3 omisiones Linux explícitas.
2. Abra `revision_juez/panel.html`; todo funciona sin internet, paquetes de Python ni privilegios.
3. Compare `lab_result/flat/resultado.json` con `lab_result/segmented/resultado.json`.
4. Lea `lab_result/REPORTE_LAB.md` para la interpretación ataque por ataque.
5. Revise `docs/security/REMEDIACION_REVISION2.md` para relacionar hallazgos, cambios y límites.
6. Revise `docs/hackathon/resultados.json` para PUE, WUE, balance hídrico y supuestos.

## Qué demuestra cada ruta

| Ruta | Evidencia |
|---|---|
| `ciberfox.py test` | Validación, detección, balance energético, auditoría e integración del proceso TShark mediante doble explícito. |
| `demo` | Pipeline local y panel con PCAP sintético; no usa una red real. |
| `lab_result` | Ejecución previamente realizada con TShark 4.6.9 real, nftables y namespaces Ubuntu. |
| `docs/hackathon/calcular.py` | Reproducción determinista de métricas y sensibilidad hídrica. |

## Validación Linux completa

El laboratorio completo requiere Ubuntu 24.04, root e internet durante la instalación. No es necesario para revisar los artefactos incluidos.

```bash
sudo bash lab/setup_ubuntu.sh
sudo python3 lab/run_lab.py --tshark /opt/tshark-4.6.9/bin/tshark --out revision_completa
```

La topología usa exclusivamente `192.0.2.0/24`, reservado para documentación, dentro de namespaces sin ruta a la red real.

## Interpretación responsable

- `INCOMPLETE` en los resultados es deliberado: el analizador marca tráfico cifrado o filas ambiguas como no inspeccionado.
- Cero falsos positivos describe solo el escenario sintético incluido.
- La energía TEG y el ahorro de agua son modelos; falta una prueba física en Mérida.
- El sistema alerta y genera evidencia; no bloquea ni acciona equipos industriales.
