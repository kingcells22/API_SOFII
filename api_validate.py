import os
import tempfile
import uuid
import traceback
import asyncio
from datetime import datetime, timezone
import requests
import base64
import urllib.request
from asn1crypto import x509

from flask import Flask, request, jsonify
from flask_cors import CORS

from pyhanko.sign import signers
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.validate import async_validate_path
from pyhanko_certvalidator.errors import RevokedError, ExpiredError, PathValidationError
from pyhanko_certvalidator.authority import CertTrustAnchor

app = Flask(__name__)
# Habilitar CORS para permitir consumo desde web
CORS(app)

def create_temp_file(file_storage, suffix=""):
    temp_dir = tempfile.gettempdir()
    unique_filename = f"{uuid.uuid4().hex}_{suffix}"
    temp_path = os.path.join(temp_dir, unique_filename)
    file_storage.save(temp_path)
    return temp_path

def _load_signer(p12_path: str, password: str) -> signers.SimpleSigner:
    with open(p12_path, 'rb') as f:
        p12_data = f.read()
        
    try:
        signer = signers.SimpleSigner.load_pkcs12(
            pfx_file=p12_path,
            passphrase=password.encode('utf-8')
        )
        return signer
    except Exception as e:
        err_msg = str(e).lower()
        if "invalid password" in err_msg or "mac verify failure" in err_msg or "bad decrypt" in err_msg or "utf-8" in err_msg or "could not load key material" in err_msg:
            raise Exception("Clave errada o formato de certificado no soportado.")
        raise Exception(f"Error interno: {e}")

def validate_cert_status(signer) -> str:
    try:
        cert = signer.signing_cert
        now = datetime.now(timezone.utc)
        
        if cert.not_valid_after < now:
            return "Vencido"
        if cert.not_valid_before > now:
            return "Inválido (Aún no activo)"
            
        try:
            serial_int = cert.serial_number
            serial_hex = f"{serial_int:X}"
            if len(serial_hex) % 2 != 0:
                serial_hex = "0" + serial_hex
            full_serial = ":".join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))
            
            _obf_key = "eENxdDdaNU45SXU5"
            _obf_header = "SFRVQV9FRk9T"
            _k = base64.b64decode(_obf_key).decode('utf-8')[::-1]
            _h = base64.b64decode(_obf_header).decode('utf-8')[::-1]
            
            url = "https://verificador.fii.gob.ve/ocspVerifySerial.php"
            headers = {_h: _k}
            data = {"serial": full_serial}
            
            response = requests.post(url, headers=headers, data=data, timeout=8)
            
            if response.status_code == 200:
                respuesta_json = response.json()
                estado_certificado = respuesta_json.get("status", "").lower()
                
                if estado_certificado in ["valid", "good"]:
                    return "Válido (Validado en línea / OCSP)"
                elif estado_certificado == "revoked":
                    return "Revocado"
        except Exception:
            pass

        async def run_validation():
            certs_in_p12 = []
            if signer.cert_registry:
                for c in signer.cert_registry:
                    certs_in_p12.append(c)
            
            trust_anchors = []
            for c in certs_in_p12:
                if c.serial_number != cert.serial_number:
                    trust_anchors.append(CertTrustAnchor(c))
                    
            if not trust_anchors:
                try:
                    aia = cert.authority_information_access_value
                    if aia:
                        issuer_url = None
                        for desc in aia:
                            if desc['access_method'].native == 'ca_issuers':
                                issuer_url = desc['access_location'].native
                                break
                        if issuer_url:
                            with urllib.request.urlopen(issuer_url, timeout=5) as response:
                                cert_bytes = response.read()
                            issuer_cert = x509.Certificate.load(cert_bytes)
                            if issuer_cert:
                                trust_anchors.append(CertTrustAnchor(issuer_cert))
                                certs_in_p12.append(issuer_cert)
                except Exception:
                    pass
                    
            if not trust_anchors:
                trust_anchors.append(CertTrustAnchor(cert))
                
            try:
                context_soft = ValidationContext(
                    trust_roots=trust_anchors,
                    allow_fetching=True,
                    other_certs=certs_in_p12,
                    revocation_mode='soft-fail'
                )
                try:
                    paths = await context_soft.path_builder.async_build_paths(cert)
                    for p in paths:
                        try:
                            await async_validate_path(context_soft, p)
                            return "Válido (Sin conexión / No verificado en línea)"
                        except RevokedError:
                            return "Revocado"
                        except ExpiredError:
                            return "Vencido"
                        except PathValidationError:
                            continue
                except Exception:
                    pass

                return "Válido (Sin conexión / No verificado en línea)"
            except Exception as e:
                err_lower = str(e).lower()
                if "revoked" in err_lower: return "Revocado"
                if "expired" in err_lower or "vencid" in err_lower: return "Vencido"
                return "Válido (Sin conexión / No verificado en línea)"

        return asyncio.run(run_validation())

    except Exception as e:
        return f"Indeterminado (Excepción interna: {str(e)})"

def get_cert_info(p12_path: str, password: str) -> dict:
    try:
        signer = _load_signer(p12_path, password)
        cert = signer.signing_cert
        
        subject_native = cert.subject.native
        issuer_native = cert.issuer.native
        
        tipo_cert = "SHA256 RSA"
        try:
            native_algo = None
            try:
                native_algo = cert['signature_algorithm']['algorithm'].native
            except Exception:
                pass
                
            if not native_algo:
                try:
                    native_algo = cert.signature_algo
                except Exception:
                    pass
                    
            if native_algo:
                algo_str = str(native_algo).upper()
                
                hash_part = "SHA256"
                if "SHA512" in algo_str: hash_part = "SHA512"
                elif "SHA384" in algo_str: hash_part = "SHA384"
                elif "SHA224" in algo_str: hash_part = "SHA224"
                elif "SHA1" in algo_str: hash_part = "SHA1"
                elif "MD5" in algo_str: hash_part = "MD5"
                    
                crypto_part = "RSA"
                if "ECDSA" in algo_str: crypto_part = "ECDSA"
                elif "DSA" in algo_str: crypto_part = "DSA"
                elif "ED25519" in algo_str: crypto_part = "ED25519"
                    
                tipo_cert = f"{hash_part} {crypto_part}"
        except Exception:
            pass
                
        nombre = subject_native.get('common_name', cert.subject.human_friendly)
        if isinstance(nombre, list) and len(nombre) > 0: nombre = nombre[0]
        
        cargo = subject_native.get('title', '')
        if isinstance(cargo, list) and len(cargo) > 0: cargo = cargo[0]
            
        institucion = subject_native.get('organization_name', '')
        if isinstance(institucion, list) and len(institucion) > 0: institucion = institucion[0]
        if not institucion:
            institucion = subject_native.get('organizational_unit_name', '')
            if isinstance(institucion, list) and len(institucion) > 0: institucion = institucion[0]
        if not institucion: institucion = "Ninguna"
            
        serial_int = cert.serial_number
        serial_hex = f"{serial_int:X}"
        if len(serial_hex) % 2 != 0: serial_hex = "0" + serial_hex
        full_serial = ":".join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))
        
        serial_parts = full_serial.split(":")
        short_serial = ":".join(serial_parts[-2:]) if len(serial_parts) >= 2 else full_serial
        
        email = subject_native.get('email_address', '')
        if isinstance(email, list) and len(email) > 0: email = email[0]
        if not email:
            email = subject_native.get('email', '')
            if isinstance(email, list) and len(email) > 0: email = email[0]
        if not email:
            email = subject_native.get('rfc822_name', '')
            if isinstance(email, list) and len(email) > 0: email = email[0]
        if not email: email = "No especificado"
            
        issuer_name = issuer_native.get('common_name', cert.issuer.human_friendly)
        if isinstance(issuer_name, list) and len(issuer_name) > 0: issuer_name = issuer_name[0]
            
        estado = validate_cert_status(signer)
        
        return {
            "tipo_cert": tipo_cert,
            "subject": nombre,
            "title": cargo,
            "organization": institucion,
            "serial_short": short_serial,
            "serial_full": full_serial,
            "email": email,
            "issuer": issuer_name,
            "not_valid_before": cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S"),
            "not_valid_after": cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
            "status": estado,
        }
    except Exception as e:
        raise Exception(f"Error al leer el certificado. Verifique la contraseña o el archivo: {e}")

# ==============================================================================
# ENDPOINT PÚBLICO: VALIDACIÓN DE CERTIFICADO
# Ruta: /api/v1/certificado/validar
# ==============================================================================
@app.route("/api/v1/certificado/validar", methods=["POST"])
def validar_certificado_api():
    """
    API pública para validación de certificados por terceros.
    Recibe un archivo .p12 y una contraseña, retorna la información 
    y el status del certificado en formato JSON.
    """
    if 'certificado' not in request.files:
        return jsonify({
            "success": False,
            "error": "Falta el archivo certificado (.p12) en el form-data."
        }), 400
        
    if 'password' not in request.form:
        return jsonify({
            "success": False,
            "error": "Falta la contraseña (password) en el form-data."
        }), 400

    certificado = request.files['certificado']
    password = request.form['password']
    p12_path = None

    try:
        p12_path = create_temp_file(certificado, "cert.p12")
        info = get_cert_info(p12_path, password)
        return jsonify({
            "success": True,
            "data": info
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400
    finally:
        if p12_path and os.path.exists(p12_path):
            os.remove(p12_path)

if __name__ == "__main__":
    # Corriendo en el puerto 5001 para no chocar con la app principal que corre en 5000
    app.run(host='0.0.0.0', port=5001, debug=True)
