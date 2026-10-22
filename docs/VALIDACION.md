**Validación ejecutada el 22 de octubre de 2026.** Entorno: Python 3.14.5 en macOS. Solo biblioteca estándar.

`python3 -m unittest discover -s tests -v`: **22 pruebas aprobadas**, sin pruebas omitidas.

Cobertura comprobada: conservación de energía en 1,000 pasos aleatorios reproducibles; límites de almacenamiento; ausencia de generación sin gradiente; techo de Carnot del modelo; uso de respaldo ante poco calor o telemetría inválida; detección independiente del presupuesto energético; enfriamiento capaz de anular el beneficio; histéresis de carga opcional; entradas NaN/Inf; límites y campos Modbus; rechazo de versiones fuera de política; rechazo de filas ambiguas; PCAP truncado; checksums IP/TCP de la captura sintética; intervalos inválidos de telemetría; y ejecución del adaptador con un **doble de prueba**, incluyendo verificación de hash.

`python3 -m ciberfox demo --out demo_result`: ejecutado correctamente. Generó dos escenarios de 600 segundos, cada uno con 20 eventos inspeccionados y tres alertas. Los resultados eléctricos y térmicos son simulados. El JSON y el panel no contienen mediciones de potencia del equipo en que se ejecutó la prueba.

**No ejecutado:** TShark real (no instalado), prueba continua de red, benchmark de rendimiento, validación de todas las fragmentaciones TCP, aislamiento de SO para entradas hostiles, integración I2C/serial, control de hardware, mediciones físicas de TEG, consumo real del gateway o impacto real en enfriamiento.

La prueba con doble de TShark solo comprueba la orquestación de subprocesos, validación y manejo de campos. No demuestra que el binario Wireshark decodifique el PCAP como esperamos. El archivo `demo_result/pcap_expected.json` contiene el resultado que deberá verificarse al disponer del ejecutable real.

No se afirma certificación industrial, ausencia de vulnerabilidades ni huella de carbono neta cero.
