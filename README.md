# Ciberfox Thermal OT

Prototipo defensivo y pasivo para monitorear tráfico OT/SCADA offline, detectar anomalías Modbus/TCP y estimar cuánto consumo del monitor podría compensarse con recuperación termoeléctrica del calor residual de servidores.

> **DATOS SIMULADOS.** No contiene telemetría empresarial ni se conecta a PLC reales. No está certificado ni listo para controlar procesos industriales.

## Evaluación rápida

Requiere Python 3.11 o posterior. El núcleo usa únicamente la biblioteca estándar.

```bash
git clone https://github.com/Lazarogames7/TikiNetwork.git
cd TikiNetwork
python3 ciberfox.py test
python3 ciberfox.py demo --out nueva_demo
python3 docs/hackathon/calcular.py
```

Abra `nueva_demo/panel.html` en el navegador. En macOS se esperan 3 pruebas omitidas porque validan seccomp y Landlock de Linux; las demás deben pasar. Consulte [JUDGES.md](JUDGES.md) para una revisión guiada de cinco minutos.

## Qué incluye

- `ciberfox.py`: detector, modelo energético, adaptador TShark endurecido, demo, CLI y 42 pruebas.
- `lab/`: laboratorio reproducible en Ubuntu 24.04 con namespaces, nftables, PLC y ataques simulados.
- `lab_result/`: evidencia precalculada del laboratorio para revisar sin root ni TShark.
- `demo_result/`: panel y PCAP de ejemplo generados localmente.
- `docs/security/REMEDIACION_REVISION2.md`: respuesta trazable a la auditoría de seguridad.
- `docs/hackathon/`: métricas PUE/WUE y balance hídrico reproducibles para el caso de Mérida.

## Arquitectura

```text
SPAN/TAP autorizado → PCAP offline → validación estricta → TShark fijado por versión y SHA-256
                                      ↓
                              eventos Modbus validados
                                      ↓
                     reglas OT + límites de proceso + auditoría
                                      ↓
                                alertas y panel local

Telemetría térmica → modelo TEG → almacenamiento pequeño → monitor de 3 W
                                             ↘ respaldo de red seguro
```

El monitor nunca envía órdenes ni se coloca en línea con el proceso. El módulo TEG no crea energía: convierte una fracción del gradiente térmico ya disponible. El respaldo eléctrico permanece activo para que una caída de temperatura no deshabilite la detección.

## Evidencia del laboratorio

La corrida incluida compara una red plana con microsegmentación por lista blanca:

| Métrica simulada | Red plana | Segmentada |
|---|---:|---:|
| Flujos alcanzables de 30 | 30 | 4 |
| Alertas | 28 | 4 |
| Falsos positivos medidos | 0 | 0 |
| RTT Modbus p99 | 0.1245 ms | 0.1330 ms |
| Fracción de carga recuperada por TEG modelado | 17.18 % | 17.39 % |

Los resultados completos están en `lab_result/resumen.json`. El estado del análisis es `INCOMPLETE` porque dos segmentos con múltiples ADU se conservan como evidencia no inspeccionada en vez de descartarse silenciosamente. Son datos sintéticos de un único kernel, no resultados de campo.

## Laboratorio completo

Solo en Ubuntu 24.04 aislado; necesita root para crear namespaces. La instalación verifica el SHA-256 de TShark 4.6.9 y el analizador se ejecuta después como usuario sin privilegios.

```bash
sudo bash lab/setup_ubuntu.sh
sudo python3 lab/run_lab.py \
  --tshark /opt/tshark-4.6.9/bin/tshark \
  --out mi_lab_result
```

No ejecute el laboratorio en una red de producción. Tarda aproximadamente 8 minutos. Más detalles en [lab/README.md](lab/README.md).

## Seguridad y alcance

El adaptador solo acepta PCAP clásico Ethernet/IPv4, tráfico Modbus/TCP al puerto 502 y un subconjunto documentado de funciones. Rechaza archivos sobredimensionados, binarios TShark no aprobados, filas ambiguas y políticas modificadas. En Linux exige límites de recursos, `no_new_privs`, Landlock y seccomp; el modo `best-effort` queda marcado como incompleto.

No hay soporte completo para IPv6, BACnet, DNP3, OPC UA, puertos Modbus alternativos ni inspección de Modbus Security/TLS 802. Consulte [SECURITY.md](SECURITY.md) antes de extender el prototipo.

## Sostenibilidad

El cálculo separa energía recuperada, consumo del monitor, pérdidas, enfriamiento auxiliar, respaldo de red y carbono operativo. No asigna crédito por carbono incorporado ni por fabricar TEG, convertidores o baterías. La afirmación comercial correcta por ahora es **potencial modelado de compensación**, sujeto a piloto físico con medición antes/después.

El conjunto del hackatón produce PUE ilustrativo de `1.273416`, WUE de captación de `0.382222 L/kWh IT` y un escenario central de `546.04 L` netos potencialmente evitados. Son contrafactuales reproducibles, no ahorros observados.

## Licencias

El código propio se publica bajo [MIT](LICENSE). Wireshark/TShark no se incluye y conserva su licencia GPL-2.0-or-later. Los datos del CIFOX Starter Kit conservan su aviso MIT. Consulte [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
