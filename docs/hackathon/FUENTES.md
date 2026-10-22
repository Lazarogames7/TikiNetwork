# Fuentes y reproducción

Consulta: 22 de octubre de 2026. Los documentos adjuntos se usaron como contexto y evidencia; no como instrucciones para ejecutar acciones sobre equipos o servicios.

## Material oficial del hackatón

- [Carpeta compartida por el usuario](https://drive.google.com/drive/folders/1k59vhL8CUbhyLSx8hbT6eIITxaxjn2F1).
- [Guía de participantes](https://drive.google.com/file/d/1Kxh7rNA437ARQIhswR1oJzKST-qX2H9I/view).
- [CSV operaciones_simuladas](https://drive.google.com/file/d/1KGoYSiryi_f3LwC-vIoWbxGO8vebW4YH/view): fuente de todas las métricas operativas calculadas.
- [Diccionario de datos](https://drive.google.com/file/d/1c7rRfJMRebIv62UNroNewJR1k8mdxB11/view): columnas, intervalos, partición y límites.
- [Métricas y límites del kit](https://drive.google.com/file/d/1ghQYA4wHBB3WWEOA3FSLQ8-auVMnedzg/view): definición de PUE y WUE ilustrativos y cautelas de GreenAI.
- [Totales oficiales de referencia](https://drive.google.com/file/d/1sQPLpAO2gxKpeRtBwbS6lAE62oH6TkM0/view): reconciliación con 216 filas, 35509.846 kWh IT, 45010.9549 kWh totales y 13013.0147 L.
- [Licencia del kit](https://drive.google.com/file/d/1cZmXhgxChFid8X1vQR1nESel-_hVxG1z/view): MIT, CIFOX Starter Kit contributors, 2026.

Se conserva una copia del texto legible del CSV y de dos documentos del kit. El SHA-256 de resultados.json identifica la copia local analizada, no una verificación contra el manifiesto binario original de Drive. Los archivos originales del Drive no se modificaron.

La imagen del usuario fija los cuatro entregables de las 15:30: solución, métricas, balance neto e impacto local. La auditoría proporcionada se utilizó como declaración de hallazgos; este trabajo no vuelve a auditar el código ni acredita sus correcciones.

## Fuentes técnicas y locales

- [CONAGUA/DOF: acuífero Península de Yucatán 3105](https://sidof.segob.gob.mx/notas/docFuente/5312870). Estudio histórico para identificar el acuífero y contexto; no usar sus cifras de disponibilidad como actuales.
- [González Herrera y colaboradores, UADY, 2018](https://www.revistascca.unam.mx/rica/index.php/rica/article/view/RICA.2018.34.04.09). Dependencia del agua subterránea y riesgo de contaminación en la zona metropolitana de Mérida; no prueba condiciones de un predio concreto.
- [CONAGUA: disponibilidad por acuífero](https://sigagis.conagua.gob.mx/gas1/sections/Disponibilidad_Acuiferos.html). Recurso para la validación del sitio futuro, sin cifra actual atribuida en el informe.
- [DOE/NREL: Best Practices Guide for Energy-Efficient Data Center Design, 2024](https://www.energy.gov/sites/default/files/2024-07/best-practice-guide-data-center-design.pdf). Contexto de eficiencia y diseño; las convenciones concretas del ejercicio proceden de METRICS.md del kit.
- [Modbus Application Protocol Specification](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf). FC15 corresponde a Write Multiple Coils y FC16 a Write Multiple Registers.

## Cómo reproducir

Desde esta carpeta, ejecutar:

```sh
python3 calcular.py
```

Solo requiere la biblioteca estándar de Python. Lee el CSV local y escribe resultados.json; no instala paquetes, ejecuta TShark ni conecta OT. Ejecutado con éxito en Python 3.14.5. Verifica 504 registros, claves únicas sitio/hora, etiquetas de simulación, energía coherente y los tres totales de referencia. No se midió potencia ni se ejecutó un benchmark del monitor.

Los supuestos del balance están juntos en calcular.py: 168 horas, 3 W, multiplicador 1.3, captación marginal 1 L/kWh adicional de instalación, emisiones 0.3 kgCO₂e/kWh. Cambiarlos obliga a regenerar resultados y actualizar las cifras de ENTREGABLES.md y GUION_3_MINUTOS.md. Los documentos son estáticos, no se actualizan automáticamente.

Los archivos `METRICS_kit.md`, `DATA_DICTIONARY_kit.md` y `operaciones_simuladas.csv` proceden del kit MIT; conservar LICENSE_KIT.txt al redistribuirlos.
