# Seguridad

Ciberfox es un prototipo académico defensivo. No debe controlar PLC, SCADA, BMS ni procesos industriales.

## Uso admitido

- PCAP obtenidos con autorización y analizados offline.
- Binario TShark mantenido, fijado por versión y SHA-256.
- Usuario sin privilegios; `sandbox=require` para evidencia formal.
- Datos simulados o previamente anonimizados.

## Límites conocidos

- Cobertura limitada a Ethernet/IPv4 y Modbus/TCP destino 502.
- Las filas con múltiples ADU y el tráfico TLS 802 se reportan como no inspeccionados.
- La identidad por IP no sustituye autenticación criptográfica de activos.
- La cadena de auditoría detecta alteración interna, pero necesita anclar externamente el último hash para detectar truncamiento final.
- El sandbox completo se validó en Ubuntu 24.04; macOS `best-effort` no ofrece aislamiento equivalente.
- El modelo TEG no incluye carbono incorporado ni valida hardware físico.

La auditoría original está en `docs/AUDITORIA_SEGURIDAD.md` y la remediación de revisión 2 en `docs/security/REMEDIACION_REVISION2.md`.

## Reporte responsable

Reporte vulnerabilidades por un canal privado a los mantenedores. No publique credenciales, PCAP de clientes, direcciones de planta ni detalles explotables de instalaciones reales. Incluya versión, plataforma, pasos mínimos y efecto observado.
