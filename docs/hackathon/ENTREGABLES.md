# Ciberfox Thermal OT · Mérida
## Propuesta para CIFOX AguaSegura AI · 22 de octubre de 2026

**DATOS SIMULADOS.** Documento para presentación y revisión del equipo. El kit contiene instalaciones ficticias: no son mediciones de Mérida. Los resultados aritméticos son reproducibles; los ahorros dependen de un contrafactual y supuestos, no son resultados de campo. Las correcciones de seguridad que realiza el equipo están pendientes de integrar y verificar.

**Propuesta:** monitorear de forma pasiva los sistemas OT que gobiernan bombas, válvulas y refrigeración de centros de datos; detectar cambios sospechosos y desviaciones operativas, y entregar al operador evidencia que permita intervenir antes de desperdiciar agua o energía. Evaluar recuperación termoeléctrica como suministro auxiliar del monitor.

## 1. Solución: diseño, arquitectura y demo

### Cliente y problema

Empresas medianas y grandes de Mérida con centros de datos o instalaciones con refrigeración y control industrial. El caso prioritario tiene uso de agua medible y una operación capaz de atender alertas. Una instalación de enfriamiento exclusivamente por aire puede obtener valor de seguridad, pero el ahorro directo de agua de este caso no se transfiere automáticamente a ella.

Una configuración indebida o una falla puede prolongar una purga, alterar una consigna o producir sobreconsumo. Una alerta OT no demuestra un ciberataque y una fuga puede tener causas mecánicas: el sistema debe informar ambas posibilidades.

### Arquitectura propuesta

```text
PLC / SCADA / BMS ─────────────── operación industrial
          │ copia de tráfico mediante TAP o SPAN
          ▼
Captura mínima → análisis TShark aislado → campos OT normalizados
                                               │
Medidores de agua y energía → series temporales ┤
                                               ▼
                            reglas explicables y correlación
                                               ▼
                       alerta + evidencia + coste estimado
                                               ▼
                         operador valida y corrige la causa
                                               ▼
                          comparación antes/después y registro

Calor residual → módulo TEG → convertidor → almacenamiento → monitor
                                         respaldo eléctrico medido
```

La ruta de análisis recibe una copia; no se coloca en serie con el control. Esto evita introducir una dependencia de la latencia del analizador en la ruta industrial, pero hay que medir pérdida de captura y retraso de alertas. Una caída del sensor debe producir un aviso de pérdida de cobertura.

**Alcance actual frente a propuesta:** el prototipo anterior demuestra eventos Modbus simulados y un modelo energético. El CSV del kit permite calcular métricas ambientales, pero no contiene paquetes, direcciones IP ni transacciones Modbus. La integración de ambas fuentes es trabajo futuro; no hay que presentar el CSV como una captura Wireshark. Este paquete agrega un análisis reproducible del kit y un escenario de intervención.

### Demo de tres minutos

1. Mostrar el rótulo DATOS SIMULADOS, los tres sitios y las métricas calculadas.
2. Elegir SIM-B y mostrar las ocho filas de `fuga_agua`. Esa etiqueta se usa para evaluar; un detector no debe leer `scenario` ni `simulated_anomaly` como entradas.
3. Explicar la desviación respecto al cociente de referencia y representar una alerta. El cálculo entregado no implementa un nuevo detector ni demuestra su latencia.
4. Mostrar qué cambia si el operador elimina 0 %, 25 %, 50 % o 100 % del exceso estimado desde la segunda hora.
5. Mostrar coste semanal del monitor y dejar visible que el beneficio de carbono aún requiere medición.

No conectar la demo a PLC reales. Usar la demo Modbus anterior solo después de incorporar las correcciones del equipo y repetir su validación.

### Seguridad y aceptación

La auditoría recibida es una lista de hallazgos del equipo, no una certificación. Antes de un piloto deben verificarse aislamiento real del proceso analizador, límites de memoria/CPU/archivos y colas, mínimo privilegio, versión mantenida de TShark, trazabilidad y acceso al panel, configuración por instalación y pruebas con tráfico inválido. Una lista de IP permitidas no autentica al emisor. La cobertura actual no equivale a cobertura de todos los comandos Modbus, IPv6 o protocolos industriales.

Corrección terminológica para la auditoría: Modbus FC15 escribe múltiples bobinas; FC16 escribe múltiples registros. Fuente: especificación oficial enlazada en FUENTES.md.

Registrar: protocolos y comandos cubiertos; paquetes descartados; latencia p50/p95; precisión y recall por clase; falsas alertas por hora; disponibilidad; CPU, RSS y energía medida. No usar “100 % seguro”. Los resultados sobre anomalías sintéticas sencillas no validan protección empresarial.

## 2. Métricas reproducibles

Fuente: CSV del kit oficial, 504 filas, tres sitios × 168 intervalos horarios, del 12 al 18 de octubre de 2026 UTC. Referencia: primeras 72 horas por sitio. Evaluación: siguientes 96. El script comprueba unicidad sitio/hora y reproduce los totales oficiales de referencia.

- PUE ilustrativo = Σ energía total / Σ energía IT.
- WUE de captación ilustrativo = Σ agua captada in situ / Σ energía IT, en L/kWh IT.
- Siempre mismo periodo y perímetro. No promediar ratios horarios sin ponderación.

| Perímetro | Filas | Energía IT kWh | Energía total kWh | Agua captada L | PUE | WUE captación L/kWh IT |
|---|---:|---:|---:|---:|---:|---:|
| Todos, semana | 504 | 82 656.4237 | 105 256.0051 | 31 593.1444 | 1.273416 | 0.382222 |
| Referencia | 216 | 35 509.8460 | 45 010.9549 | 13 013.0147 | 1.267563 | 0.366462 |
| Evaluación | 288 | 47 146.5777 | 60 245.0502 | 18 580.1297 | 1.277824 | 0.394093 |
| SIM-B, semana | 168 | 27 581.3955 | 34 120.2198 | 24 849.4334 | 1.237074 | 0.900949 |

Referencia y evaluación tienen distinta duración: la diferencia entre sus totales no demuestra mejora ni deterioro causado por una intervención. Los tres sitios tampoco son un experimento controlado de tecnologías de enfriamiento.

La convención del kit mide captación, no consumo neto después de retornos. No es un informe WUE certificado. Presentamos PUE y WUE, que cumplen la alternativa “y/o” de la imagen. No publicamos CUE real porque faltan emisiones y mezcla energética verificadas del sitio. En un piloto, CUE = emisiones operativas dentro del perímetro / energía IT; declarar emisiones incluidas y factor con fuente y año.

## 3. Balance neto: agua, energía y carbono

### Contrafactual hídrico sobre SIM-B

El cociente de captación de SIM-B en referencia es **0.853688 L/kWh IT**. Se usa como aproximación al agua esperada a igual energía IT, no como modelo físico calibrado. No controla clima, carga térmica ni purgas; el kit no representa el clima real de Mérida.

Para cada hora de fuga:

`exceso_estimado = max(0, agua_observada − energía_IT × WUE_referencia_SIM-B)`

Las ocho horas suman **2 184.3658 L captados** y **1 251.9823 L de exceso estimado**. Suponemos que la primera hora se pierde y que la intervención puede actuar antes del segundo intervalo. Quedan **1 093.3998 L potencialmente evitables**. No se deduce una respuesta en segundos de datos horarios. Tampoco se prueba que la fuga sea causada por un ataque.

### Coste del monitoreo durante toda la semana

Un monitor para SIM-B funcionando 168 horas, incluidos los periodos sin incidentes:

| Parámetro | Valor | Naturaleza |
|---|---:|---|
| Potencia media de todo el monitor | 3 W | Supuesto por validar, no medición ni garantía |
| Energía IT del monitor | 0.504 kWh | 3 × 168 / 1000 |
| Multiplicador de energía de instalación | 1.3 | Supuesto incremental; no el PUE observado ni una medición |
| Electricidad adicional de instalación | 0.6552 kWh | 0.504 × 1.3 |
| Captación marginal onsite | 1 L/kWh adicional de instalación | Supuesto; no confundir con WUE por kWh IT |
| Captación adicional | 0.6552 L | 0.6552 × 1 |
| Factor de emisión | 0.3 kgCO₂e/kWh | Hipótesis ilustrativa, no factor oficial de México |
| Emisiones operativas adicionales | 0.19656 kgCO₂e | 0.6552 × 0.3 |
| Crédito TEG / ahorro eléctrico del proceso | 0 / 0 kWh | Sin crédito hasta demostrarlo |

El monitor usa reglas en la propuesta inicial: no hay entrenamiento ni inferencia de IA demostrados en este paquete. Para responder al balance del hackatón se cuenta el sistema completo de monitoreo. Si se añade ML, su entrenamiento, inferencia, almacenamiento y equipos auxiliares deben incorporarse al mismo perímetro; no se puede presentar su consumo como cero.

### Sensibilidad a una intervención efectiva

`captación_neta_evitada = fracción_recuperada × 1093.3998 − 0.6552`

| Exceso eliminado desde la segunda hora | Captación bruta evitada L | Captación neta evitada L |
|---|---:|---:|
| 0 %: nadie corrige | 0.00 | −0.66 |
| 25 % | 273.35 | 272.69 |
| 50 % | 546.70 | **546.04** |
| 100 % | 1 093.40 | 1 092.74 |

**Escenario de exposición recomendado:** 50 % de recuperación hipotética: **546.04 L netos de captación evitada en una semana simulada**, contando el monitor toda la semana. El 50 % es una hipótesis, no una probabilidad ni resultado experimental. No multiplicar por 52 como ahorro anual: faltan frecuencia real de incidentes, eficacia y disponibilidad.

Este es un balance parcial de captación onsite. Excluye agua de generación eléctrica, fabricación y retornos; esos datos faltantes impiden afirmar reducción de huella hídrica completa. Se deben comparar también los volúmenes absolutos: añadir energía IT al denominador puede mejorar artificialmente WUE sin ahorrar agua.

### Cómo sostener la propuesta térmica y de carbono

La propuesta TEG aprovecha una diferencia de temperatura entre dos caras. El calor residual por sí solo no garantiza potencia útil; hay pérdidas de conversión, almacenamiento y posibles penalizaciones de ventilación o refrigeración. No bloquear flujo de aire ni modificar la refrigeración de producción para alimentar el sensor.

En una prueba de banco medir a la vez temperaturas de ambas caras, potencia útil entregada, consumo del monitor, respaldo de red, ventiladores/bombas adicionales y estado inicial/final de batería. Comparar con y sin TEG a la misma carga, ambiente, duración y trabajo de monitoreo. Una batería descargada no es energía recuperada durante la prueba.

`ahorro_eléctrico_TEG = reducción_medida_del_respaldo − electricidad_auxiliar_adicional`

`CO₂e_evitable = electricidad_neta_evitada × factor_verificado − emisiones_incorporadas_asignadas`

Comparar dos preguntas diferentes: (a) ¿TEG reduce consumo frente al mismo monitor alimentado desde red?; (b) ¿la solución completa reduce emisiones frente a no instalarla? En el escenario calculado, sin crédito TEG ni ahorro del proceso, **se añaden 0.19656 kgCO₂e operativos**. Para una reducción operativa neta, el ahorro eléctrico del proceso y/o recuperación útil, sin doble contabilizar, debe superar los 0.6552 kWh adicionales semanales; fabricar e instalar el equipo aumenta el umbral de ciclo de vida. El ahorro de agua no demuestra automáticamente ahorro de carbono.

## 4. Impacto local en Mérida

El acuífero regional de referencia es **Península de Yucatán, clave 3105**, identificado por CONAGUA. El estudio de UADY publicado en 2018 describe la dependencia del agua subterránea y la vulnerabilidad a contaminación por la permeabilidad del medio; ubica zonas de alto riesgo en el área metropolitana de Mérida. Son antecedentes hidrogeológicos, no una medición actual de disponibilidad o contaminación de un predio. [CONAGUA/DOF](https://sidof.segob.gob.mx/notas/docFuente/5312870), [estudio UADY](https://www.revistascca.unam.mx/rica/index.php/rica/article/view/RICA.2018.34.04.09).

La cadena de impacto propuesta es: alerta → validación → corrección → menor captación operativa → menor demanda al suministro que abastece la instalación. Si ese suministro proviene del acuífero, puede reducir extracción asociada. Debe identificarse pozo propio, proveedor de red o agua reutilizada antes de atribuir el volumen al acuífero.

En el escenario del 50 %, el resultado equivale a **0.546 m³ de captación onsite evitada**, no a 0.546 m³ de recarga, agua potable creada o consumo neto necesariamente evitado. Tampoco demuestra mejora de calidad del agua ni reducción proporcional del bombeo de la red.

Para validar en una empresa: documentar fuente y medidor de abastecimiento; volumen de captación y retorno; calidad y destino de descarga; circuito de enfriamiento; producción/carga IT y clima comparables; actuación y tiempo de respuesta. Usar disponibilidad vigente de CONAGUA para contextualizar el sitio, sin reutilizar cifras históricas como actuales. No se afirma que el acuífero esté sobreexplotado.

## Qué entregar y qué completar

Entregar este documento, resultados.json, calcular.py, CSV del kit, fuentes y guion. Añadir nombre del equipo e integrantes. El paquete no ha sido enviado al hackatón.

Antes de exponer: ejecutar el cálculo; mostrar el origen oficial y DATOS SIMULADOS; ensayar tres minutos; disponer de captura o video local de la demo. No esperar a que un arreglo pendiente se convierta en una afirmación de seguridad.

Para pasar de propuesta a piloto faltan: versión corregida y validada del software; medición real de potencia y TEG; validación de cobertura y tasa de alertas; medidores de agua y energía; fuente hídrica del sitio; intervención operativa documentada y comparación controlada. El valor empresarial propuesto es seguridad OT con trazabilidad de agua y energía; aún no es un ahorro contractual garantizable.
