# Procedencia de la revisión 2

- Archivo recibido: `ciberfox-revision2.zip`
- SHA-256 del archivo: `42096bf3a1afc13a3ee0a083f34dc20b0e0118357adc9c30d675e4fa4c1e8ba9`
- Fecha de integración: 2026-10-22
- Validación del contenedor: 35 entradas, sin rutas absolutas, `..` ni enlaces simbólicos.

Durante la integración se corrigieron además la ejecución del doble de TShark en macOS `best-effort`, el uso de `shell=True` en la topología, el manejo condicional de `--tshark` y la descarga HTTPS del instalador. El historial Git conserva la implementación anterior.
