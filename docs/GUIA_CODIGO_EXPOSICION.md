# Cómo funciona y cómo está programado Ciberfox

Esta guía está pensada para explicar el código frente a los jueces en tres o cuatro minutos sin recorrerlo línea por línea.

## Explicación de 30 segundos

> “Ciberfox recibe una captura PCAP autorizada y offline. Primero valida el archivo; después ejecuta TShark como un proceso externo aislado y fijado por versión y SHA-256. TShark convierte los paquetes Modbus en campos estructurados. Nuestro detector compara cada evento con una política de activos, orígenes, registros y límites físicos. En paralelo, un administrador energético calcula qué parte de los 3 W del monitor podría cubrirse con un TEG y cuánto debe aportar el respaldo eléctrico. El laboratorio crea una planta y una red completamente simuladas para medir detección, segmentación, latencia y consumo.”

## Por qué está en un solo archivo

`ciberfox.py` se entrega como un archivo ejecutable para que los jueces puedan probarlo con Python 3.11 o posterior sin instalar paquetes. Internamente conserva separadores que representan módulos lógicos:

1. Modelo energético.
2. Eventos, políticas y detector OT.
3. Sandbox del proceso TShark.
4. Adaptador y parser de TShark.
5. Bitácora encadenada.
6. Demo, CLI y pruebas.

El laboratorio Linux permanece separado en `lab/` porque crea procesos, namespaces y reglas de red.

## Flujo completo del programa

```text
captura.pcap
    │
    ▼
validate_pcap() ── tamaño, formato, paquetes y longitudes
    │
    ▼
decode() ── versión + SHA-256 + sandbox ──► TShark externo
    │                                          │
    │                                          ▼
    └────────────────────────────── filas de campos Modbus
                                               │
                                               ▼
                                      parse_row() → Event
                                               │
                                               ▼
                                     Detector.inspect()
                                               │
                                               ▼
                                  alertas + salud + evidencia

telemetría térmica → illustrative_teg() → EnergyManager.step()
                                               │
                                               ▼
                               recuperación + respaldo + pérdidas
```

## 1. Modelo energético

### `illustrative_teg(hot_c, cold_c, modules)`

Recibe las temperaturas de las caras caliente y fría del módulo y calcula un modelo didáctico:

- `delta = hot_c - cold_c`.
- Tensión de circuito abierto por efecto Seebeck.
- Potencia con carga adaptada.
- Límite superior de Carnot.
- Eficiencia supuesta del convertidor.

El código toma el menor valor entre la potencia eléctrica modelada y el límite físico. Si el gradiente es menor de 5 K, declara cero generación útil.

### `EnergyManager.step()`

Se ejecuta una vez por muestra. Mantiene un estado de almacenamiento y reparte la energía en este orden:

1. Alimentación directa de la carga.
2. Descarga del almacenamiento si existe déficit.
3. Respaldo eléctrico para cualquier déficit restante.
4. Carga del almacenamiento si existe excedente.
5. Registro de energía recortada y pérdidas.

Si la telemetría está vencida, excede límites térmicos o es inconsistente, no reclama energía recuperada y pasa a `BACKUP_TELEMETRY_FAULT`. La seguridad crítica nunca depende de que exista calor.

### `summarize()`

Suma Wh recuperados, carga, energía de red, enfriamiento adicional, pérdidas y almacenamiento. Compara contra la misma carga sin recuperación y estima carbono operativo mediante un factor configurable. Declara explícitamente que el carbono incorporado no está incluido.

## 2. Representación del tráfico OT

### `Event`

Es una `dataclass` inmutable. Representa una solicitud Modbus con:

- tiempo;
- IP origen y destino;
- unidad y función Modbus;
- dirección, valor, cantidad o lista de valores;
- puerto, flujo TCP y transaction ID.

`Event.validate()` rechaza IP inválidas, valores fuera de rango, listas demasiado grandes y escrituras FC06 incompletas.

### `Policy`

Define el comportamiento permitido por instalación:

- orígenes autorizados para escribir;
- orígenes autorizados para leer;
- PLC y unit IDs conocidos;
- registros y bobinas permitidos;
- intervalos físicos aceptables;
- parámetros energéticos.

`load_policy()` acepta un JSON pequeño, regular y sin enlace simbólico. Valida claves, tipos y rangos, y puede exigir un SHA-256 específico.

## 3. Motor de detección

`Detector.inspect(event)` usa reglas deterministas. Esto facilita explicar por qué se produjo cada alerta:

| Alerta | Condición |
|---|---|
| `UNEXPECTED_ASSET` | Destino o unidad fuera de la política. |
| `UNAUTHORIZED_READ` | Lectura desde un origen que no debe consultar el PLC. |
| `READ_FLOOD` | 100 lecturas no autorizadas dentro de la ventana. |
| `UNAUTHORIZED_COMMAND` | Escritura desde un origen no autorizado. |
| `UNAPPROVED_REGISTER` | Escritura en una dirección fuera del mapa permitido. |
| `PROCESS_LIMIT` | Valor válido para Modbus pero peligroso para el proceso. |
| `UNSUPPORTED_CONTROL` | Función de control sin cobertura suficiente. |
| `UNINSPECTED_CONTROL` | Fila ambigua que incluye o podría incluir una escritura. |
| `ENCRYPTED_UNINSPECTED` | Flujo cifrado que el sensor no puede interpretar. |

Las lecturas repetidas se agrupan para evitar que una inundación genere miles de alertas y oculte las importantes. El detector genera evidencia y solicita revisión humana; no envía comandos ni bloquea equipos.

## 4. Adaptador TShark

### Validación anterior a TShark

`validate_pcap()` acepta solamente PCAP clásico Ethernet de microsegundos, con tamaño máximo de 16 MiB y hasta 50,000 registros. Recorre las cabeceras para detectar truncamientos o longitudes inválidas antes de llamar al parser externo.

### Ejecución controlada

`decode()`:

1. Rechaza root y plataformas no POSIX para el adaptador formal.
2. Exige una ruta absoluta a TShark.
3. Rechaza binarios con permisos inseguros.
4. Calcula y compara el SHA-256 aprobado.
5. Copia el PCAP validado a un directorio temporal.
6. Construye los argumentos como una lista; no usa shell.
7. Aplica tiempo máximo, límites de salida y directorios de configuración vacíos.
8. Ejecuta el descriptor exacto que fue verificado.

En Linux, `limited_exec_main()` combina límites de recursos, `no_new_privs`, namespaces, Landlock y seccomp. Seccomp impide sockets y otras llamadas peligrosas; Landlock limita los archivos visibles.

### Conversión a eventos

TShark emite campos tabulados. `parse_row()` convierte cada fila en un `Event` y trata de forma específica FC05, FC15 y FC16. Si una fila trae varias ADU inseparables, `rejected_evidence()` conserva origen, funciones y flujo; el resultado se marca `INCOMPLETE` y el detector genera una alerta de tráfico no inspeccionado.

## 5. Bitácora

`audit_append()` escribe registros JSON canónicos unidos mediante el hash del registro anterior. `audit_verify()` recalcula la cadena y detecta modificaciones internas. Para detectar el borrado del final del archivo, el último hash debe guardarse fuera del equipo.

## 6. Interfaz de línea de comandos

```bash
python3 ciberfox.py test
python3 ciberfox.py demo --out demo_jueces
python3 ciberfox.py analyze-pcap --pcap CAPTURA --tshark TSHARK \
  --approved-sha256 HASH --policy POLITICA
python3 ciberfox.py replay-power --csv TELEMETRIA
python3 ciberfox.py audit-verify --log BITACORA
```

La demo utiliza direcciones reservadas para documentación y no abre conexiones de red.

## 7. Cómo está programada la simulación

### `lab/topology.py`

Crea seis namespaces Linux y un gateway. Cada host tiene una dirección `/32` y una única ruta por el gateway, por lo que incluso el tráfico entre equipos de la misma zona atraviesa nftables. Todos los comandos se ejecutan como listas de argumentos con `shell=False`.

### `lab/nft_flat.nft` y `lab/nft_segmented.nft`

- `flat`: permite los 30 flujos posibles entre los seis equipos.
- `segmented`: usa lista blanca y deja cuatro flujos normalmente; una ventana de mantenimiento habilita temporalmente un quinto.

### `lab/modbus.py`

Implementa un cliente y servidor Modbus/TCP mínimo con la biblioteca estándar. Construye y valida la cabecera MBAP y cubre las funciones necesarias para el escenario: FC03, FC04, FC05, FC06, FC15 y FC16.

### `lab/plc_sim.py`

El PLC virtual mantiene registros y un modelo térmico de primer orden:

```text
C · dTi/dt = Q − UA(bomba) · (Ti − Ts)
```

- La consigna de la bomba está en el registro 100.
- La bomba cambia como máximo 10 % por segundo.
- La temperatura y el caudal se recalculan cada segundo.
- Los valores se escriben en registros Modbus y en `plant.csv`.
- Una bandera simula la deriva de un sensor sin crear tráfico de red.

### `lab/actors.py`

Programa el comportamiento normal y los eventos hostiles:

- SCADA consulta cada segundo y hace ajustes válidos.
- Historian consulta cada cinco segundos.
- `probe` mide qué servicios son alcanzables.
- `latency` realiza 2,000 lecturas y calcula mediana, media y p99.
- `attack` ejecuta A1–A11 y registra lo que realmente envió en `verdad_terreno.jsonl`.

Los ataques cubren escritura no autorizada, reconocimiento, inundación, límites físicos, registro no aprobado, abuso de historian, ventana de mantenimiento y varias ADU dentro del mismo segmento TCP.

### `lab/run_lab.py`

Es el orquestador:

1. Levanta la topología plana.
2. Inicia PLC, SCADA, historian y servicios ficticios.
3. Mide superficie y latencia.
4. Captura el enlace del PLC mediante `tcpdump`.
5. Ejecuta el escenario durante 200 segundos.
6. Analiza el PCAP con la CLI real como usuario sin privilegios.
7. Compara las alertas con la verdad de terreno.
8. Reproduce la telemetría térmica en el modelo TEG.
9. Repite todo con microsegmentación.
10. Escribe JSON, CSV, PCAP y el resumen.

## 8. Qué demuestra la nueva corrida

| Métrica | Plana | Microsegmentada |
|---|---:|---:|
| Flujos alcanzables | 30/30 | 4/30 |
| RTT mediana / p99 | 0.056 / 0.103 ms | 0.053 / 0.086 ms |
| Paquetes capturados | 5,518 | 1,393 |
| Alertas | 28 | 4 |
| Falsas alarmas sobre 434 solicitudes normales | 0 | 0 |
| Ataques de red detectados | 10/10 | 4 detectados + 6 bloqueados |

El ataque A5 altera el valor del sensor dentro del PLC simulado y no viaja por la red, por lo que el detector pasivo no puede verlo. A11 demuestra otro límite: una escritura escondida detrás de una lectura puede atravesar un filtro que solo mira la primera ADU; Ciberfox la marca como `UNINSPECTED_CONTROL`, pero no la bloquea.

## Guion técnico de tres minutos

> “El programa tiene dos pipelines que se encuentran en el reporte. El primero es de ciberseguridad. Validamos un PCAP, ejecutamos TShark aislado y transformamos sus campos en objetos `Event`. Cada evento pasa por una política que define activos, orígenes, registros y límites físicos. Las reglas son deterministas, por lo que cada alerta incluye una razón verificable.”

> “El segundo pipeline es energético. A partir de temperaturas modelamos un TEG, contabilizamos conversión, almacenamiento, pérdidas y respaldo. Si la telemetría falla o no hay gradiente, el monitor sigue funcionando desde la red: nunca sacrificamos detección para aparentar ahorro.”

> “Para validarlo construimos seis hosts en namespaces Linux. Un PLC virtual calcula la temperatura de entrada de servidores y expone registros Modbus. SCADA e historian generan operación normal; once ataques y una recuperación se registran como verdad de terreno. Corremos exactamente el mismo escenario en una red plana y una segmentada, capturamos el tráfico y calificamos las alertas.”

> “La red plana permitió 30 de 30 flujos y el detector identificó los 10 ataques de red. La segmentación redujo la superficie a 4 flujos, bloqueó seis ataques y dejó cuatro para el análisis de contenido. Eso demuestra que segmentación y detección se complementan: una lista blanca no reconoce por sí sola a un SCADA comprometido que envía un valor peligroso.”

## Preguntas que pueden hacerte

### “¿Es inteligencia artificial?”

No en este MVP. Usa reglas deterministas y un modelo físico simple porque son explicables, requieren pocos recursos y permiten justificar cada alerta. Un modelo estadístico futuro podría detectar deriva de sensores, pero necesitaría datos reales y control de falsos positivos.

### “¿Por qué el resultado dice `INCOMPLETE`?”

Porque hubo segmentos con varias ADU que TShark devolvió en una fila no separable. El sistema conserva evidencia y declara el límite en lugar de fingir cobertura completa.

### “¿La segmentación reemplaza al detector?”

No. Bloquea orígenes que nunca deberían llegar al PLC, pero un SCADA permitido y comprometido atraviesa la red. El detector reconoce registros no aprobados y valores fuera de límites.

### “¿Por qué Python?”

Permite un prototipo portable, legible y sin dependencias externas para el núcleo. Para producción, el sensor de alto caudal podría migrar componentes críticos a Rust o C y mantener las mismas políticas y formatos de evidencia.

### “¿Por qué no bloquear automáticamente?”

En OT, bloquear incorrectamente puede detener un proceso físico. El MVP es pasivo. Las reglas nftables preventivas se validan en el laboratorio, pero cualquier respuesta automática en producción exigiría pruebas de seguridad funcional y aprobación del operador.

### “¿Qué es dato real y qué es supuesto?”

Los paquetes, tiempos y resultados fueron medidos dentro del laboratorio simulado. La planta, ataques y temperaturas son sintéticos. La potencia TEG y los factores de carbono son modelos. No hay todavía una prueba en un centro de datos real.
