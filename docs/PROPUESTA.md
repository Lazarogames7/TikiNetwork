**Ciberfox: monitoreo OT con recuperación de calor residual.** Propuesta y prototipo de laboratorio, 22 de octubre de 2026.

La propuesta es alimentar parcial o, si las mediciones lo permiten, totalmente un sensor de monitoreo con electricidad recuperada del calor residual de servidores. El sistema conservará respaldo eléctrico y almacenamiento. La detección crítica no se reduce para cumplir una meta energética. No se promete consumo neto cero: hay que medir también ventiladores, bombas, conversión, almacenamiento y el resto de la infraestructura añadida.

**Hay dos etapas comercialmente razonables.** Primero, alimentar un nodo de telemetría de muy bajo consumo con un generador termoeléctrico, mientras un gateway existente realiza análisis de tráfico y su consumo incremental se contabiliza. Después, dimensionar un conjunto de generadores para alimentar también el analizador completo, solo si los ensayos térmicos y eléctricos demuestran energía suficiente en la peor condición. Un microcontrolador de telemetría no equivale a un equipo ejecutando TShark y Ethernet continuamente.

Hay investigación experimental sobre nodos de monitoreo de centros de datos alimentados por generadores termoeléctricos. El trabajo de Álvarez-Carulla y colaboradores estudia un nodo y su circuito de aprovechamiento energético; su eficiencia superior al 92 % corresponde al sistema electrónico estudiado, no a convertir el 92 % del calor de un servidor en electricidad. Es un antecedente para un nodo de baja potencia, no evidencia de autonomía para nuestro analizador. [Scientific Reports, 2023](https://www.nature.com/articles/s41598-023-28378-6).

**El calor necesita una diferencia de temperatura para producir electricidad.** Un TEG usa el efecto Seebeck: una cara caliente y una fría producen una tensión. No sirve rodear el dispositivo de aire caliente si ambas caras terminan a la misma temperatura. La cara fría necesita un camino térmico adecuado y el calor restante todavía debe evacuarse.

En el modelo ilustrativo usamos:

```text
deltaT = max(Th - Tc, 0)
Voc = alpha * deltaT
Pmax_ideal_carga_adaptada = N * Voc² / (4 * R_interna)
eta_Carnot = 1 - Tc_kelvin / Th_kelvin
Pbus = min(Pmax_ideal, Qhot_supuesto * eta_Carnot) * eta_DC
```

Carnot es un techo termodinámico, nunca una eficiencia comercial predicha. A 60 °C y 30 °C el techo es aproximadamente 9 %. La conversión real está por debajo. El modelo supone que cada módulo conserva ese gradiente, lo cual **no se mantiene automáticamente al agregar módulos**: comparten un flujo térmico finito y modifican la refrigeración. No es un modelo térmico acoplado ni una herramienta de dimensionamiento de hardware.

**El pipeline energético propuesto tiene seis pasos.**

1. Recuperar calor desde un punto aprobado del circuito secundario de enfriamiento o un intercambiador de laboratorio. Evitar colocar un módulo entre CPU y disipador sin rediseño y validación térmica del fabricante.
2. Mantener el lado frío con un intercambiador/disipador adecuado. No elevar la temperatura de los servidores para aumentar la generación.
3. Convertir la salida variable del TEG mediante un circuito de harvesting y seguimiento del punto de máxima potencia. Verificar arranque en frío, tensión, corriente, rango térmico y consumo propio.
4. Alimentar un almacenamiento protegido: supercapacitor o batería con electrónica compatible. El diseño requiere limitación de corriente, protección, autonomía y vida útil verificadas.
5. Conmutar automáticamente entre recuperación, almacenamiento y respaldo mediante un power-path físico. La continuidad no debe depender de que Python alcance a ejecutar una instrucción.
6. Medir potencia recuperada en el bus DC, carga total, respaldo y aumento del consumo de refrigeración. El supervisor de software registra y recomienda estados; este prototipo no conmuta ningún circuito.

El LTC3108 es un ejemplo documentado de circuito de harvesting de muy baja tensión, apropiado para estudiar un nodo pequeño; el fabricante describe aplicaciones de sensado y adquisición. **No se propone como fuente suficiente para un gateway de varios watts.** El PMIC definitivo depende de las curvas eléctricas del TEG y del consumo medido. [Analog Devices](https://www.analog.com/en/products/ltc3108.html).

**El pipeline de seguridad se mantiene independiente del presupuesto térmico.**

1. En una futura instalación autorizada: puerto espejo/TAP, interfaz de captura sin IP y gestión por interfaz separada. La selección/configuración del espejo debe verificar ambos sentidos del tráfico y pérdidas.
2. Captura con dumpcap actualizado y privilegios mínimos, sin poner el analizador en el camino del control. Rotación y límites de disco. Este repositorio solo procesa archivos offline; no instala captura continua.
3. TShark aislado como proceso: resolución de nombres desactivada y lista limitada de protocolos.
4. Extracción de timestamp, origen, destino, unidad, función, dirección y valor; validación estricta.
5. Reglas críticas: comandos desde origen no autorizado, destino/unidad inesperados, registro no permitido y valor fuera del intervalo de laboratorio.
6. Evidencia y aviso al operador. Funciones fuera de cobertura se notifican; no se bloquean PLCs ni se modifican consignas.

El MVP cubre semántica de escritura de un registro Modbus FC06. Las otras funciones de control generan revisión, no una falsa afirmación de seguridad. No incluye BACnet, autenticación real de la identidad de origen, mapa de fabricante, ventanas de mantenimiento, reensamblado propio ni un motor de respuesta. Una IP autorizada no prueba identidad y una lectura normal no demuestra ausencia de ataque.

**La política energética tiene tres estados y no corta la carga crítica.**

| Estado | Decisión modelada |
|---|---|
| CORE_ONLY | Mantener análisis crítico; posponer reportes opcionales. Usar recuperación, almacenamiento disponible y respaldo. |
| CORE_PLUS_REPORTS | Permitir carga opcional solo con excedente y almacenamiento suficiente; aplicar histéresis. |
| BACKUP_TELEMETRY_FAULT | Ante medición obsoleta, inconsistente o límite térmico excedido: no acreditar recuperación, mantener carga crítica por respaldo y solicitar revisión. |

Los umbrales 75 °C/50 °C y 5 segundos del código son **valores de laboratorio**, no límites seguros universales para servidores ni TEGs. La protección térmica real debe operar en hardware y conservar el camino de evacuación de calor. El código no simula un fallo simultáneo del respaldo ni garantiza disponibilidad del equipo real.

**La sustentabilidad se verifica con un balance, no con el número de módulos.**

El código modela almacenamiento vacío al inicio para no atribuir carga previa de origen desconocido a recuperación. Contabiliza pérdidas de carga/descarga, límites de potencia, energía excedente descartada y reserva mínima. La potencia de harvesting se toma después de la conversión DC; no se aplica dos veces su pérdida.

```text
E_red_real = E_respaldo_DC / eta_AC_DC + E_enfriamiento_adicional
E_referencia = E_misma_carga_de_monitoreo / eta_AC_DC
Ahorro_vs_monitoreo_convencional = E_referencia - E_red_real
Incremento_vs_no_monitoreo = E_red_real
CO2e_operativo_evitado_estimado = Ahorro_kWh * factor_kgCO2e_por_kWh
```

El factor de carbono 0.4 kgCO2e/kWh y la eficiencia AC/DC de 90 % son ejemplos configurados, no datos locales verificados. El balance puede dar ahorro negativo si el sistema aumenta mucho el enfriamiento. No se contabiliza exportación a la red ni se inventa crédito por calor simplemente disponible. Si compite con otro uso útil del calor, debe evaluarse ese costo de oportunidad.

El producto completo deberá incluir energía incremental del switch, gateway, almacenamiento, transmisión y refrigeración, y amortizar las emisiones de fabricación del TEG, intercambiadores y batería. La metodología SCI ofrece un marco para declarar energía, intensidad de carbono, emisiones incorporadas y unidad funcional. El prototipo solo informa un balance eléctrico operativo y **no calcula una huella completa SCI**. [Green Software Foundation](https://sci.greensoftware.foundation/).

**La demostración generada contiene dos casos hipotéticos de diez minutos.**

| Caso | Porción de carga abastecida por recuperación | Electricidad adicional respecto a no instalar monitoreo |
|---|---:|---:|
| 4 módulos ilustrativos | 20.2 % | 0.468 Wh |
| 32 módulos ilustrativos | 90.1 % | 0.084 Wh |

Ambos mantienen los mismos 20 eventos inspeccionados y tres alertas. El segundo admite más reportes opcionales, de modo que su carga total es mayor; cada uno se compara contra una referencia de **su misma carga**, no contra el otro para afirmar eficiencia equivalente. Las diferencias se deben a parámetros de simulación. No constituyen mediciones de TEGs, watts reales de TShark, precisión de detección empresarial o latencia de red.

**La reducción de superficie de software se realiza sin bifurcar Wireshark.**

No se copia código de Wireshark ni se invocan APIs internas. Se utilizan opciones CLI documentadas y campos vigentes. La revisión se hizo el 22 de octubre de 2026; el adaptador acepta la rama estable 4.6 desde el parche 4.6.9 y bloquea otras ramas hasta revisarlas. Esto es un control de compatibilidad temporal, no una garantía de que todas las versiones futuras de esa rama sean seguras.

Se fija el hash aprobado del ejecutable, se rechaza ejecución como root, se pasa una lista de argumentos sin shell, se usa configuración personal vacía y se redirigen directorios de plugins/extcap. Se limita el tamaño y formato de entrada; el subproceso tiene tiempo, CPU, archivos y memoria limitados donde el SO lo permite. `-n` evita resolución de nombres y `--only-protocols` restringe la disección a la cadena necesaria para Ethernet/IPv4/Modbus.

Los campos `modbus.regval_uint16` y `modbus.reference_num` están documentados; no se usa el antiguo `modbus.reg16`. La documentación de TShark especifica las opciones usadas. La versión 4.6.9 corrige vulnerabilidades, por lo que no se recomienda reutilizar una instalación vieja por conveniencia. [Manual TShark](https://www.wireshark.org/docs/man-pages/tshark.html), [campos Modbus](https://www.wireshark.org/docs/dfref/m/modbus.html), [notas 4.6.9](https://www.wireshark.org/docs/relnotes/wireshark-4.6.9.html).

Deshabilitar disectores no elimina su código del binario ni demuestra que toda dependencia o plugin global sea inocuo. Los límites del proceso no son un sandbox de seguridad. Antes de procesar capturas de terceros: paquete de origen firmado verificado, instalación inmutable sin extensiones, revisión de bibliotecas, aislamiento de SO sin red y acceso de archivos mínimo, y pruebas de integración con capturas representativas. El hash identifica un binario previamente aprobado; copiar el hash de un archivo desconocido no autentica su procedencia.

**El alcance probado y el pendiente están separados.**

Se verificaron el balance energético, sus invariantes, las reglas de laboratorio, campos ambiguos, entradas inválidas y la estructura/checksums del PCAP sintético. TShark no está instalado en el entorno de entrega: el adaptador se revisó contra documentación, pero su ejecución real y la decodificación del PCAP quedan pendientes. No se realizaron mediciones físicas, benchmarking industrial ni ensayos térmicos.

**Para avanzar a un piloto hay cinco puertas de aceptación.**

1. Medir el consumo completo del nodo/gateway a tráfico nominal y pico, incluyendo la captura. No asumir que será 3 W porque lo diga la simulación.
2. Caracterizar el TEG y el power-path en banco con carga variable, arranque, cambios de temperatura y pérdida de la fuente. La energía usada por una placa calefactora de prueba se cuenta; no es recuperación gratuita.
3. Medir efecto sobre temperatura del servidor, ventiladores, bombas y potencia total bajo carga de cómputo equivalente. Rechazar diseños que comprometan refrigeración o produzcan balance ambiental negativo.
4. Validar TShark, aislamiento, segmentación TCP, pérdidas, reinicios, flujos persistentes y funciones Modbus adicionales. Hacer prueba física de continuidad al perder calor y al perder telemetría.
5. Medir emisiones operativas y fabricación, durabilidad, mantenimiento y costo. Solo entonces valorar la afirmación «monitoreo alimentado completamente con calor residual» para el rango de operación validado.

El argumento para el hackatón es: **«recuperamos energía residual para reducir la demanda eléctrica del monitoreo OT, sin sacrificar detección, y publicamos un balance verificable que incluye respaldo y refrigeración»**.
