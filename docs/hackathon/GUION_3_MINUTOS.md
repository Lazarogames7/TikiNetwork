# Guion de exposición · Ciberfox Thermal OT

**Mantener visible: DATOS SIMULADOS.** Completar integrantes antes de presentar.

## 0:00–0:35 · Problema y cliente

“En Mérida proponemos proteger los sistemas industriales que gobiernan el agua y la refrigeración de centros de datos. Una configuración indebida o una falla puede mantener una pérdida de agua durante horas. Nuestro objetivo es detectar antes y dar al operador evidencia para corregirla.”

## 0:35–1:10 · Solución

“Ciberfox recibe una copia del tráfico OT y combina señales de red con agua y energía. El análisis es pasivo y la actuación la valida una persona. El prototipo Modbus y la integración ambiental tienen alcances diferentes: el kit que presentamos contiene series simuladas, no paquetes reales. Estamos incorporando hallazgos de una auditoría antes de considerar un piloto.”

## 1:10–1:45 · Métricas

“Procesamos las 504 filas oficiales. El PUE ilustrativo agregado es 1.2734 y el cociente hídrico de captación es 0.3822 litros por kWh IT. Usamos cocientes de sumas y declaramos el perímetro. Son datos ficticios; no describen un centro de datos de Mérida.”

## 1:45–2:20 · Balance

“En SIM-B hay ocho horas de fuga simulada. Estimamos el exceso con su referencia y descontamos la primera hora. Si una intervención eliminara la mitad del exceso restante, evitaría 546.70 litros brutos. Un monitor supuesto de tres watts, operando toda la semana y con auxiliares, añadiría 0.6552 litros: quedan 546.04 litros netos de captación evitada. Si nadie corrige, el beneficio desaparece.”

## 2:20–2:45 · Calor y carbono

“Proponemos recuperar parte del calor mediante módulos termoeléctricos, con respaldo y medición del balance completo. No afirmamos energía gratis. Por ahora no asignamos crédito al TEG: el escenario agrega 0.197 kilos de CO₂ equivalente. La siguiente prueba debe demostrar que la recuperación y el ahorro del proceso superan ese coste.”

## 2:45–3:00 · Impacto y siguiente paso

“Para Mérida importa reducir demanda al suministro subterráneo. Nuestro resultado potencial es captación evitada, no recarga del acuífero. Buscamos validar con una instalación, medidores y una intervención documentada.”

## Preguntas previsibles

- **¿Dónde está la IA?** La base propuesta usa reglas explicables y de bajo coste. ML es una ampliación que requiere justificar precisión y consumo. Si la evaluación exige un modelo IA implementado, hay que incorporar y evaluar ese componente; no renombrar reglas como un modelo entrenado.
- **¿Ahorra 546 litros en cualquier empresa?** No: es un escenario sobre un sitio ficticio, con recuperación supuesta del 50 %.
- **¿Tienen consumo cero?** No. El TEG requiere un gradiente útil y un balance medido; el respaldo sigue previsto.
- **¿Ya corrige ataques?** Alerta y apoya al operador. No remedia vulnerabilidades del PLC ni demuestra prevención automática.
- **¿El WUE es oficial/certificado?** Es el cociente de captación ilustrativo definido por el kit, con su perímetro declarado.
- **¿Cuánto cuesta?** Aún falta dimensionar tráfico, hardware, integración, soporte y TEG; no hay precio validado.
