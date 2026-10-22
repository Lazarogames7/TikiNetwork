# Estado de remediación — AUDITORIA_SEGURIDAD.md (22 de octubre de 2026, revisión 2)

**Verificado en esta revisión:** `python3 ciberfox.py test` → **42 pruebas OK, ninguna omitida** (usuario no-root, Ubuntu 24.04, kernel 6.18, Python 3.13). Ejecución de extremo a extremo con **TShark 4.6.9 real** (compilado desde la fuente oficial, SHA256 verificado) bajo el sandbox obligatorio, y en el laboratorio de red simulada (`lab/`). **macOS y hardware: NO probados.**

La revisión 1 pasaba sus pruebas, pero sus pruebas de FC05/FC15 usaban filas inventadas. Con TShark real, esa revisión rechazaba en silencio todas las escrituras FC05 y FC15, y también las escrituras pegadas a otra ADU. La revisión 2 lo corrige con filas copiadas de la salida real.

| ID | Estado | Qué se hizo / qué falta |
|---|---|---|
| H1 | Hecho en Linux; sin probar en macOS | Seis capas, en orden: límites (incl. `RLIMIT_AS`), `no_new_privs`, namespaces de usuario y red sin privilegios (sin interfaces de red), **Landlock** (lectura/ejecución solo en directorios del sistema y del binario; escritura solo en el directorio temporal del análisis), seccomp (sockets, ptrace, `process_vm_*`, `io_uring_*` y **toda la ABI x32**, que en la revisión 1 permitía evadir la lista), y hash verificado sobre el mismo descriptor que se ejecuta. Comprobado: TShark no puede leer `~/archivo`; `socket()` por x32 devuelve EPERM. `--sandbox require` exige Landlock en Linux. **Falta:** macOS (`sandbox-exec` no aísla archivos con el perfil actual; sin probar), `RLIMIT_NPROC`, contenedor/VM. |
| H2 | Hecho (salvo cifrado, por definición) | FC05 se lee de `modbus.data` (`ff00`/`0000`), que es lo que imprime TShark real; el valor ilegal da `MALFORMED_WRITE`. FC15 valida cada bit contra el mapa de bobinas. Las filas que no se pueden separar (varias ADU en un segmento) ya no se descartan: generan `UNINSPECTED_CONTROL` si contienen una escritura, o `UNINSPECTED_REQUEST` si no. **Política de cifrado:** el tráfico al puerto 802 (Modbus/TCP Security) se cuenta, genera `ENCRYPTED_UNINSPECTED` por flujo y marca el análisis `INCOMPLETE`; no se descifra. El texto de `scope` ahora describe la cobertura real. |
| H3 | Parcial (límite físico) | Política externa (revisión 1). Se añaden `flow_id` (`tcp.stream`) y `transaction_id` (`mbtcp.trans_id`) como evidencia de flujo en cada evento. La identidad sigue siendo IP: un sensor pasivo no puede autenticar al origen; eso requiere 802.1X, mTLS o Modbus/TLS en los equipos. |
| H4 | Hecho | Sin cambios respecto a la revisión 1. |
| H5 | Parcial | Bitácora encadenada (revisión 1). Ahora también se registran los errores de carga de la política. **Falta:** API con mTLS, roles y rate limiting (no existe API), y anclar el último hash fuera del equipo. |
| M1 | Hecho | Sin cambios. `frame-ancestors` no se puede fijar desde `<meta>`; requiere cabecera HTTP si algún día se sirve el panel. |
| M2 | Hecho | Sin cambios. |
| M3 | Hecho | La revisión 1 re-hasheaba y luego ejecutaba **por ruta** (seguía habiendo ventana). Ahora el binario se abre una vez con `O_NOFOLLOW`, se hashea ese descriptor y se ejecuta ese mismo descriptor (`fexecve`). Las bibliotecas dinámicas siguen sin verificarse. |
| M4 | Hecho | Verificado contra la salida real: `TShark (Wireshark) 4.6.9 (Git commit 2d548b197c75).` |
| M5 | Hecho | Sin cambios. |
| B1 | Hecho | `UNAUTHORIZED_READ` ahora se **agrega**: una alerta por origen, destino y unidad cada 60 s, con `occurrences`, y una sola escalada `READ_FLOOD` al superar 100 lecturas en la ventana (umbral de laboratorio). En el laboratorio, la revisión 1 generó 2036 alertas por una sola inundación y enterró las 8 importantes. |
| B2 | Hecho al integrar | El código propio quedó bajo MIT con encabezados SPDX; Wireshark/TShark no se redistribuye y se documenta por separado como GPL-2.0-or-later en `THIRD_PARTY_NOTICES.md`. |
| B3 | Hecho | Validado con TShark 4.6.9 real. La 4.6.6 (PPA de Ubuntu) se rechaza por la política de versión, como está diseñado. |
| B4 | Pendiente | Requiere mediciones físicas. |
