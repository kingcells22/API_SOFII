import os
import tempfile
import uuid
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS
from signer_engine import get_cert_info, sign_pdf

app = Flask(__name__)
# Habilitamos CORS por defecto para que NEXUS o terceros puedan consumir la API desde el navegador sin problemas
CORS(app)

def create_temp_file(file_storage, suffix=""):
    """Guarda un FileStorage de Flask en un archivo temporal seguro y retorna su ruta."""
    temp_dir = tempfile.gettempdir()
    unique_filename = f"{uuid.uuid4().hex}_{suffix}"
    temp_path = os.path.join(temp_dir, unique_filename)
    file_storage.save(temp_path)
    return temp_path

# ==============================================================================
# 1. ENDPOINT: INFORMACIÓN DEL CERTIFICADO
# Ruta: /firma/informacion-certificado
# Función: Recibe un certificado .p12 y devuelve sus datos y validez (OCSP).
# ==============================================================================
@app.route("/firma/informacion-certificado", methods=["POST"])
def obtener_informacion_certificado():
    """
    Recibe un archivo .p12 y una contraseña, retorna la información 
    estructurada del certificado y su estado de validez (incluyendo OCSP).
    """
    if 'certificado' not in request.files:
        return jsonify({"error": "Falta el archivo certificado (.p12)"}), 400
    if 'password' not in request.form:
        return jsonify({"error": "Falta la contraseña (password)"}), 400

    certificado = request.files['certificado']
    password = request.form['password']
    p12_path = None

    try:
        p12_path = create_temp_file(certificado, "cert.p12")
        info = get_cert_info(p12_path, password)
        return jsonify(info), 200
    except Exception as e:
        print(f"Error extrayendo info del certificado: {e}")
        return jsonify({"error": str(e)}), 400
    finally:
        if p12_path and os.path.exists(p12_path):
            os.remove(p12_path)


# ==============================================================================
# 2. ENDPOINT: FIRMAR PDF (ESTÁNDAR O INVISIBLE)
# Ruta: /firma/firmar-pdf
# Función: Firma un documento usando solo texto para la apariencia visual, 
#          o firma de forma invisible si las coordenadas son 0.
# ==============================================================================
@app.route('/firma/firmar-pdf', methods=['POST'])
def firmar_pdf_endpoint():
    """
    Endpoint de firma de PDF (invisible/estándar). 
    Si se mandan coordenadas de tamaño > 0, se pondrá un cuadro de texto visible.
    """
    try:
        if 'pdf' not in request.files or 'p12' not in request.files:
            return jsonify({"error": "Faltan archivos (pdf o p12)"}), 400
        
        password = request.form.get('password')
        if not password:
            return jsonify({"error": "Falta la contraseña"}), 400

        try:
            sig_x = float(request.form.get('x', 0))
            sig_y = float(request.form.get('y', 0))
            sig_width = float(request.form.get('width', 0))
            sig_height = float(request.form.get('height', 0))
            sig_page = int(request.form.get('page', 1))
            # lock_document sella el PDF post-firma
            lock_document = str(request.form.get('lock', 'false')).lower() == 'true'
        except (TypeError, ValueError):
            return jsonify({"error": "Las coordenadas (x, y, width, height) y page deben ser números válidos."}), 400

        pdf_path = create_temp_file(request.files['pdf'], "input.pdf")
        p12_path = create_temp_file(request.files['p12'], "cert.p12")
        
        nombre_original = request.form.get('pdf_name', 'documento.pdf')
        name_without_ext, ext = os.path.splitext(nombre_original)
        if not ext: ext = ".pdf"
        output_filename = f"{name_without_ext}_firmado{ext}"
        output_path = os.path.join(tempfile.gettempdir(), f"{uuid.uuid4().hex}_signed.pdf")

        try:
            sign_pdf(
                input_pdf_path=pdf_path,
                output_pdf_path=output_path,
                p12_path=p12_path,
                password=password,
                page_num=sig_page,
                x=sig_x,
                y=sig_y,
                width=sig_width,
                height=sig_height,
                lock_document=lock_document
            )
            
            with open(output_path, 'rb') as f:
                pdf_data = f.read()

            response = app.make_response(pdf_data)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename="{output_filename}"'
            return response

        except Exception as e:
            traceback.print_exc()
            return jsonify({"error": f"Fallo en la firma: {str(e)}"}), 500
        finally:
            if os.path.exists(output_path): 
                os.remove(output_path)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Error interno: {str(e)}"}), 500
    finally:
        if 'pdf_path' in locals() and pdf_path and os.path.exists(pdf_path): 
            os.remove(pdf_path)
        if 'p12_path' in locals() and p12_path and os.path.exists(p12_path): 
            os.remove(p12_path)


# ==============================================================================
# 3. ENDPOINT: FIRMAR PDF CON IMAGEN
# Ruta: /firma/firmar-pdf-imagen
# Función: Firma un documento estampando una imagen (PNG/JPG) redimensionada 
#          dentro de las coordenadas proporcionadas (bounding box).
# ==============================================================================
@app.route('/firma/firmar-pdf-imagen', methods=['POST'])
def firmar_pdf_imagen_endpoint():
    """
    Endpoint para firmar usando una imagen de fondo para el sello visual.
    La imagen escalará usando el algoritmo seguro de pyHanko.
    """
    try:
        if 'pdf' not in request.files or 'p12' not in request.files or 'image' not in request.files:
            return jsonify({"error": "Faltan archivos (pdf, p12 o image)"}), 400
        
        password = request.form.get('password')
        if not password:
            return jsonify({"error": "Falta la contraseña"}), 400

        try:
            sig_x = float(request.form.get('x', 0))
            sig_y = float(request.form.get('y', 0))
            sig_width = float(request.form.get('width', 0))
            sig_height = float(request.form.get('height', 0))
            sig_page = int(request.form.get('page', 1))
            lock_document = str(request.form.get('lock', 'false')).lower() == 'true'
        except (TypeError, ValueError):
            return jsonify({"error": "Las coordenadas y parámetros deben ser válidos."}), 400

        pdf_path = create_temp_file(request.files['pdf'], "input.pdf")
        p12_path = create_temp_file(request.files['p12'], "cert.p12")
        
        # Validar y guardar imagen temporal
        imagen = request.files['image']
        img_path = create_temp_file(imagen, "sig.img")

        nombre_original = request.form.get('pdf_name', 'documento.pdf')
        name_without_ext, ext = os.path.splitext(nombre_original)
        if not ext: ext = ".pdf"
        output_filename = f"{name_without_ext}_firmado{ext}"
        output_path = os.path.join(tempfile.gettempdir(), f"{uuid.uuid4().hex}_signed.pdf")

        try:
            sign_pdf(
                input_pdf_path=pdf_path,
                output_pdf_path=output_path,
                p12_path=p12_path,
                password=password,
                page_num=sig_page,
                x=sig_x,
                y=sig_y,
                width=sig_width,
                height=sig_height,
                lock_document=lock_document,
                image_path=img_path
            )
            
            with open(output_path, 'rb') as f:
                pdf_data = f.read()

            response = app.make_response(pdf_data)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename="{output_filename}"'
            return response

        except Exception as e:
            traceback.print_exc()
            return jsonify({"error": f"Fallo en la firma: {str(e)}"}), 500
        finally:
            if os.path.exists(output_path): os.remove(output_path)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Error interno: {str(e)}"}), 500
    finally:
        if 'pdf_path' in locals() and pdf_path and os.path.exists(pdf_path): os.remove(pdf_path)
        if 'p12_path' in locals() and p12_path and os.path.exists(p12_path): os.remove(p12_path)
        if 'img_path' in locals() and img_path and os.path.exists(img_path): os.remove(img_path)

# Este endpoint ya no debería usarse porque devolvemos el archivo en el POST 
# pero se deja por compatibilidad temporal si algún código muy viejo lo llamaba.
# ==============================================================================
# 4. ENDPOINT: DESCARGAR ARCHIVO (DEPRECADO)
# Ruta: /download/<filename>
# Función: Ya no es necesario porque la API devuelve los bytes directamente,
#          pero se deja para retrocompatibilidad y evitar errores 404 duros.
# ==============================================================================
@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    return jsonify({"error": "Este endpoint está deprecado. Los archivos ya no se guardan en el servidor."}), 404

if __name__ == "__main__":
    # Importante usar host 0.0.0.0 para escuchar externamente
    app.run(host='0.0.0.0', port=5000, debug=True)
