# Motor de Firmas y Validación - SOFII (Entorno de Desarrollo)

Este repositorio contiene el entorno completo de desarrollo y el motor principal (`signer_engine.py`) para el procesamiento de certificados digitales y firmas de la FII.

## 🚀 Características Principales
- **Firma de Documentos PDF:** Capacidad de estampar firmas digitales estándar y firmas invisibles.
- **Firma con Imagen:** Inserción de sello visual (PNG/JPG) con coordenadas dinámicas utilizando algoritmos de escalado seguro (PyHanko).
- **Extracción de Datos:** Lectura profunda de archivos `.p12` para extraer nombre, organización, correo, fechas y serial.
- **Verificación OCSP:** Diagnóstico de estado del certificado verificando localmente y contra el servidor OCSP de FIIIDT.

## 🛠️ Tecnologías
- Python 3.10+
- Flask (Microframework web)
- PyHanko / PyHanko-Certvalidator (Criptografía y manejo de PDFs)
- Asn1crypto

## ⚙️ Uso en Desarrollo
1. Crea y activa tu entorno virtual.
2. Instala los requerimientos: `pip install -r requirements.txt` (o instala los paquetes listados en `app.py`).
3. Ejecuta la aplicación: `python app.py`
4. La API de pruebas estará disponible en `http://127.0.0.1:5000`.

> **Nota de Seguridad:** Este repositorio contiene código lógico de desarrollo. Las versiones limpias para integración con terceros se manejan en otro repositorio.
> ** Debe realizar la solicitud previa, para popder acceder al repositorio de producción.
