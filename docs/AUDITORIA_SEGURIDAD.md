# Auditoría de seguridad — Ciberfox (ciberfox-thermal-ot)

**Fecha de la auditoría:** 22 de octubre de 2026
**Alcance auditado:** `/Users/Lazarog/Documents/CifoxHackaton/ciberfox-thermal-ot`
**Módulos revisados:** `ciberfox/energy.py`, `ciberfox/detector.py`, `ciberfox/tshark_adapter.py`,
`ciberfox/limited_exec.py`, `ciberfox/demo.py`, `ciberfox/__main__.py`, `tests/test_system.py`
**Contexto:** Prototipo offline de análisis de tráfico OT (Modbus/TCP) orientado a detección de comandos
de control no autorizados, con recuperación de energía térmica residual (TEG).

---

## 1. Resumen ejecutivo

El proyecto muestra una base de diseño defensiva razonable y fail-safe: el analizador **nunca envía
comandos** a PLCs, **nunca bloquea** automáticamente (siempre deriva a revisión humana), la detección
no se desactiva por ahorro energético, y las entradas (PCAP, CSV, filas TShark) están acotadas.

Sin embargo, la auditoría de seguridad identificó **debilidades relevantes** que deben resolverse antes
de que el prototipo evolucione a una solución de campo.

## 2. Verificaciones realizadas

- Suite de pruebas ejecutada (`python3 -m unittest discover -s tests -v`): **22/22 pruebas OK**
  (Python 3.14.5 en macOS, biblioteca estándar únicamente).
- Revisión estática de todos los módulos fuente en busca de patrones de riesgo:
  - Sin uso de `eval`, `exec`, `os.system`, `popen`, `shell=True`, `pickle` o deserialización.
  - El único uso de procesos externos es `subprocess` para TShark, invocado con lista de argumentos
    (sin shell) y sandbox parcial.
  - Sin secretos, claves ni credenciales hardcodeadas en el repositorio.
- Validación de artefactos de demo: PCAP sintético con rangos de documentación (RFC 5737),
  checksums IP/TCP verificados en pruebas; panel HTML sin scripts.

## 3. Hallazgos de seguridad

### 3.1 Críticos / Altos

#### H1 — El lanzador de TShark **no constituye un sandbox de seguridad** y está incompleto en macOS
- **Evidencia:** `ciberfox/limited_exec.py` aplica `RLIMIT_CORE`, `RLIMIT_CPU`, `RLIMIT_FSIZE`,
  `RLIMIT_NOFILE` y, solo si `sys.platform.startswith("linux")`, `RLIMIT_AS` (512 MiB).
- En macOS —plataforma donde se validó el prototipo— **no se aplica `RLIMIT_AS`**, por lo que el
  límite de memoria queda sin aplicar.
- Además, los *resource limits* de proceso **no son un sandbox de SO**: no se aplican seccomp, network
  namespace, mount namespace, ni drop de capabilities al proceso de TShark.
- **Impacto:** el proceso que ejecuta TShark mantiene identidad/privilegios y capacidades del host.
  Para un analizador que procesa capturas y ejecuta binarios externos, esto es un punto crítico de
  confianza antes de considerar entradas hostiles.
- **Recomendación:** reemplazar el launcher por un sandbox real (namespace de red, mount ns, seccomp,
  drop de capabilities/privilegios, o contenedor Firecracker/namespace) y alinear los *resource limits*
  a todas las plataformas soportadas.

#### H2 — Hueco de cobertura de detección que afecta la seguridad operativa
- **Evidencia:** el README y el propio adaptador declaran explícitamente que la cobertura es limitada:
  solo PCAP clásico Ethernet/IPv4, puerto 502, solo FC06, sin IPv6, sin tráfico cifrado, sin BACnet,
  sin puertos alternativos, sin variantes de Modbus.
- Funciones de escritura de control relevantes **no cubiertas** (FC05 Write Single Coil, FC15 Write
  Multiple Registers, FC16 Write Multiple Registers) no generan alerta de proceso; salen al estado
  `UNSUPPORTED_CONTROL` (revisión).
- El **tráfico cifrado** (TLS/DTLS sobre Modbus) queda fuera de la extracción → sin análisis posible.
- **Impacto:** para una solución de protección OT, operar con cobertura no declarada implica que comandos
  relevantes podrían pasar sin inspección.
- **Recomendación:** ampliar el mapa de funciones soportadas, definir política de tráfico cifrado y
  documentar explícitamente el estado de cobertura antes de cualquier despliegue real.

#### H3 — Identidad/autorización de origen basada solo en IP (allowlist) incrustada en el código
- **Evidencia:** `ciberfox/detector.py` contiene `allowed = {"192.0.2.10"}`, `target = ("192.0.2.20", 1)`
  y el mapa de registros como valores fijos de laboratorio.
- No existe validación de identidad de origen más allá de la dirección IP, y los valores son
  hardcodeados en el código fuente.
- **Impacto:** allowlist de laboratorio incrustada; si se despliega el código tal cual, las políticas no
  corresponden a la planta. Además, en capturas con mirroring, la suplantación de fuente debe mitigarse
  con correlación de flujo/señal.
- **Recomendación:** inyectar configuración por despliegue, con allowlist gestionada, identidad de flujo
  robusta y validación de integridad.

#### H4 — Configuración de laboratorio hardcodeada (umbrales, potencias, tiempos, factor CO₂)
- **Evidencia:** `energy.py` y `demo.py` incluyen umbrales (75 °C/50 °C, 5 s, 3 W críticos, 0.5 W
  opcionales, 0.1 Wh capacidad, eficiencias, factor CO₂ 0.4, intervalos de registro 100/20–60, etc.).
- **Recomendación:** mover a configuración externa por despliegue; tratar como datos de laboratorio.

#### H5 — Pipeline de análisis sin autenticación/autorización ni trazabilidad de uso (gap de producto)
- **Evidencia:** el subcomando `analyze-pcap` opera por CLI local, validando un hash aprobado; no existe
  capa de autenticación, rate limiting, logging de alertas ni separación de roles en el código actual.
- Cuando se integre como gateway/API, será obligatorio incorporar autenticación (mTLS/token),
  autorización por rol y auditoría de eventos.

### 3.2 Medias

#### M1 — CSP del panel generado (`demo_result/panel.html`)
- **Evidencia:** `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'`
- Se recomienda: `object-src 'none'` explícito, `frame-ancestors 'none'`, `upgrade-insecure-requests`,
  y restringir `style-src` mediante nonce/hash o estilos externos (evitar `'unsafe-inline'`).

#### M2 — Manejo de excepciones incompleto en la CLI
- `ciberfox/__main__.py` solo captura `(ValueError, OSError, subprocess.TimeoutExpired, UnicodeError, csv.Error)`.
- Errores no contemplados (p. ej. `struct.error`, `KeyError`, `IndexError`) producirían un *stacktrace*
  con información interna al operador.

#### M3 — Condiciones de carrera (TOCTOU) en el binario de TShark
- Se verifica hash y permisos, y luego se ejecuta el binario; se recomienda verificar mediante file
  descriptor y re-verificación, evitando sustitución de archivo entre verificación y ejecución.

#### M4 — Ajuste del gate de versión de TShark
- El patrón de versión no está totalmente anclado; se sugiere reforzarlo (`fullmatch`/anclaje) para
  evitar aceptación de cadenas con sufijos no deseados.

#### M5 — Timeout fijo de TShark (25 s)
- Puede producir estado `INCOMPLETE` con capturas reales de mayor tamaño/complejidad; es una limitación
  operativa, no de seguridad, pero afecta confiabilidad del análisis.

### 3.3 Bajas / informativas

- **B1:** No se generan alertas para lecturas desde origen no autorizado (reconocimiento) — gap de
  cobertura, por diseño del MVP.
- **B2:** No existe licencia de distribución definida para el código del prototipo.
- **B3:** Pendiente validar con TShark real (no instalado en el entorno de entrega).
- **B4:** No se realizaron mediciones físicas ni benchmarks; los balances energéticos son simulados.

## 4. Aspectos positivos confirmados por la auditoría

- Postura fail-safe correcta: sin comandos enviados, sin bloqueo automático, revisión humana.
- Detección independiente del presupuesto energético.
- Límites de entrada estrictos (PCAP ≤16 MiB, ≤50 000 paquetes; CSV ≤2 MiB / ≤10 000 muestras).
- Sin superficie de ejecución de código arbitrario (sin eval/exec/shell).
- Sin secretos en el repositorio.
- Salida JSON con `allow_nan=False`.

## 5. Prioridades sugeridas para remediación

1. **Crítico (producción):** reemplazar el launcher de TShark por un sandbox de SO real; aplicar
   `RLIMIT_AS` y demás límites en todas las plataformas.
2. **Alto:** ampliar cobertura de detección (funciones de escritura, tráfico cifrado) y externalizar
   configuración (allowlist, umbrales).
3. **Alto:** diseñar la capa de autenticación/autorización y trazabilidad del pipeline de análisis.
4. **Medio:** endurecer CSP del panel, manejar excepciones globalmente, corregir TOCTOU y reforzar gate
   de versión.
5. **Medio:** definir licencias y validar contra TShark real.

---

# 6. Propuestas de solución y plan de remediación

## Prioridad 1 — Crítico (producción): reforzar el sandbox de TShark

**H1: el lanzador no es un sandbox de seguridad y está incompleto en macOS.**

*Propuesta de corrección:*
1. Sustituir `ciberfox/limited_exec.py` por un sandbox real:
   - Aplicar `RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_RSS` (cuando el SO lo soporte) en **todas** las plataformas.
   - Añadir filtro **seccomp** (BPF) con syscalls permitidas para el proceso.
   - Utilizar **namespace** de red/montaje (`unshare`) o un contenedor (Docker/podman/Firejail).
   - Realizar **drop de capabilities** y ejecución con usuario no privilegiado.
2. Mantener los *resource limits* actuales (CPU 20 s, FSIZE 32 MiB, NOFILE 64) como segunda barrera.
3. Verificar que TShark no requiera escritura fuera del sandbox (config/plugins/extcap ya se redirigen).

## Prioridad 2 — Alto: ampliar cobertura de detección y externalizar configuración

**H2: cobertura limitada de tráfico (FC06, IPv4, puerto 502, no cifrado).**

*Propuesta de corrección:*
1. Añadir al detector las funciones de escritura relevantes: **FC05** (Write Single Coil),
   **FC15** (Write Multiple Registers) y **FC16** (Write Multiple Registers), con su propio mapa de
   registros por unidad.
2. Definir política explícita para **tráfico cifrado** (TLS/DTLS sobre Modbus): requerirá captura con
   claves/DPI; documentar el estado de la cobertura antes del despliegue.
3. Mantener el reporte `UNSUPPORTED_CONTROL` para funciones no cubiertas (fail-safe correcto).

**H3 / H4: allowlist y umbrales hardcodeados.**

*Propuesta de corrección:*
1. Externalizar allowlist (`source`, `destination`, `unit`) y umbrales (temperaturas, potencias, tiempos,
   factor CO₂) a configuración por despliegue (archivo de configuración / secret manager), con respaldo en
   código por defecto solo para laboratorio.
2. Fortalecer la identidad de origen: correlación de flujo (5-tuple + secuencia/transacción) en lugar de
   IP aislada.

## Prioridad 3 — Alto: capa de seguridad del producto

**H4 / H5: falta de autenticación, autorización y trazabilidad en el pipeline.**

*Propuesta de corrección:*
1. Diseñar la API/gateway con autenticación (mTLS, tokens), autorización por rol y rate limiting.
2. Incorporar logging/auditoría de alertas (quién, cuándo, qué evento, decisión).
3. Gestionar el hash aprobado de TShark a través de secret manager / registro firmado.

## Prioridad 4 — Medio: endurecimiento técnico (M1–M5)

| ID | Propuesta de corrección |
|---|---|
| **M1** (CSP) | Añadir `object-src 'none'`, `frame-ancestors 'none'`, `upgrade-insecure-requests`; migrar a nonce/hash para `style-src` en lugar de `'unsafe-inline'`. |
| **M2** (excepciones) | Capturar excepción general (`except Exception`) en CLI y devolver error genérico (sin stacktrace) con código 2. |
| **M3** (TOCTOU) | Verificar binario vía file descriptor y re-verificación; evitar symlink (O_NOFOLLOW). |
| **M4** (versión) | Reforzar regex con `fullmatch`/anclaje. |
| **M5** (timeout) | Parametrizar timeout o escalar según tamaño de captura; manejar timeout con kill de proceso. |

## Prioridad 5 — Bajas / de gobernanza

- **B1:** Decidir y documentar política de alertas para lecturas desde origen no autorizado.
- **B2:** Definir licencia de distribución del prototipo.

---

**Nota de alcance:** esta auditoría corresponde al código y artefactos presentes en el repositorio
offline. No sustituye una auditoría de seguridad ofensiva (pentest) con capturas reales, ni una evaluación
de seguridad industrial/certificación.
