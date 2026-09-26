# Manual de Integración - API de Validación de Certificados (FII)

Este documento detalla el funcionamiento y la forma de conexión a la API de Validación de Certificados para terceros.

## 1. ¿Qué es y para qué sirve esta API?
Esta API (Interfaz de Programación de Aplicaciones) es un servicio web que permite a sistemas de terceros verificar la validez e información de un certificado digital (.p12) emitido por la FII. 

El servicio se encarga de:
- Extraer los datos del titular (nombre, correo, organización).
- Validar las fechas de vigencia.
- Consultar en tiempo real con el servidor OCSP de la FII para verificar si el certificado ha sido revocado.

---

## 2. Parámetros de Conexión para Terceros

Los terceros **no necesitan el código fuente**. Solo necesitan saber a qué dirección web enviar los datos y qué formato usar.

- **Método HTTP:** `POST`
- **URL (Endpoint):** `http://<TU_DIRECCION_IP_O_DOMINIO>:5001/api/v1/certificado/validar`
- **Tipo de Contenido (Content-Type):** `multipart/form-data`

### Parámetros a enviar en el "Body" (Cuerpo de la petición):
El sistema del tercero debe enviar obligatoriamente dos campos:

| Nombre del Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `certificado` | Archivo (File) | El archivo binario del certificado digital con extensión `.p12`. |
| `password` | Texto (Text) | La contraseña del certificado para poder leerlo. |

---

## 3. Respuestas de la API

El sistema del tercero recibirá una respuesta en formato **JSON**.

### ✅ Caso de Éxito (Código HTTP 200)
Si el certificado es leído correctamente, la API devolverá `success: true` y los datos del certificado en la llave `data`:

```json
{
  "success": true,
  "data": {
    "email": "usuario@correo.com",
    "issuer": "FIIIDT CA",
    "not_valid_after": "2025-12-31 23:59:59",
    "not_valid_before": "2024-01-01 00:00:00",
    "organization": "FII",
    "serial_full": "01:23:45:67:89:AB:CD:EF",
    "serial_short": "CD:EF",
    "status": "Válido (Validado en línea / OCSP)",
    "subject": "Juan Perez",
    "tipo_cert": "SHA256 RSA",
    "title": "Gerente"
  }
}
```
*Nota importante:* El campo `status` indicará si es "Válido", "Revocado" o "Vencido".

### ❌ Caso de Error (Código HTTP 400)
Si la contraseña es incorrecta, falta un parámetro o el archivo no es válido, se devolverá `success: false` y un mensaje de error:

```json
{
  "success": false,
  "error": "Error al leer el certificado. Verifique la contraseña o el archivo..."
}
```

---

## 4. Instrucciones para probar con Postman

Se ha proporcionado un archivo llamado `Sofii_Validation_API.postman_collection.json`. Para probarlo:

1. Abre la aplicación **Postman**.
2. En la esquina superior izquierda, haz clic en el botón **"Import"** (Importar).
3. Arrastra el archivo `.json` a la ventana, o búscalo en tus carpetas.
4. Una vez importado, verás una colección llamada *"Sofii API Validación de Certificados"*.
5. Despliega la colección y haz clic en la petición *"Validar Certificado (.p12)"*.
6. Ve a la pestaña **"Body"**.
7. En la fila de `certificado`, en la columna *Value*, haz clic en "Select File" y elige un certificado real.
8. En la fila de `password`, escribe la clave real.
9. Asegúrate de que la API esté corriendo en tu servidor, y presiona el botón azul **"Send"** (Enviar). Verás la respuesta en la parte inferior.
