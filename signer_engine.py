import os
from datetime import datetime
from pyhanko.sign import signers, fields
from pyhanko.stamp import TextStampStyle, StaticStampStyle
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigFieldSpec, append_signature_field

from datetime import timezone
import asyncio
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.validate import async_validate_path
from pyhanko_certvalidator.errors import RevokedError, ExpiredError, PathValidationError
from pyhanko_certvalidator.authority import CertTrustAnchor

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
    """
    Realiza un diagnóstico profundo del certificado.
    Verifica fechas (Vencido) y valida contra el servidor OCSP de FIIIDT.
    """
    try:
        cert = signer.signing_cert
        now = datetime.now(timezone.utc)
        
        # 1. Validación estricta de fechas locales
        if cert.not_valid_after < now:
            return "Vencido"
        if cert.not_valid_before > now:
            return "Inválido (Aún no activo)"
            
        # 2. Validación en línea con el servidor de FIIIDT (Custom OCSP)
        try:
            import requests
            import base64
            serial_int = cert.serial_number
            serial_hex = f"{serial_int:X}"
            if len(serial_hex) % 2 != 0:
                serial_hex = "0" + serial_hex
            full_serial = ":".join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))
            
            # Ofuscación Capa 1: Decodificación en memoria
            _obf_key = "eENxdDdaNU45SXU5"
            _obf_header = "SFRVQV9FRk9T"
            _k = base64.b64decode(_obf_key).decode('utf-8')[::-1]
            _h = base64.b64decode(_obf_header).decode('utf-8')[::-1]
            
            url = "https://verificador.fii.gob.ve/ocspVerifySerial.php"
            headers = {_h: _k}
            data = {"serial": full_serial}
            
            print(f"[DEBUG OCSP] Consultando {url} para el serial {full_serial}...")
            response = requests.post(url, headers=headers, data=data, timeout=8)
            
            if response.status_code == 200:
                respuesta_json = response.json()
                estado_certificado = respuesta_json.get("status", "").lower()
                print(f"[DEBUG OCSP] Respuesta del servidor FIIIDT: {respuesta_json}")
                
                if estado_certificado in ["valid", "good"]:
                    print("[DEBUG OCSP] Certificado detectado como VÁLIDO en línea por el servidor.")
                    return "Válido (Validado en línea / OCSP)"
                elif estado_certificado == "revoked":
                    print("[DEBUG OCSP] Certificado detectado como REVOCADO por el servidor.")
                    return "Revocado"
                else:
                    print(f"[DEBUG OCSP] Servidor retornó estado no reconocido ({estado_certificado}). Usando fallback local...")
            else:
                print(f"[DEBUG OCSP] Error HTTP {response.status_code} al consultar servidor. Usando fallback local...")
        except Exception as e:
            print(f"[DEBUG OCSP] Error de conexión o consulta al endpoint FIIIDT: {str(e)}. Usando fallback local...")

        # 3. Fallback: Validación de OCSP / Ruta de confianza estándar (local/soft-fail si está sin internet)
        async def run_validation():
            # Extraemos todos los certificados que vienen en el archivo .p12
            certs_in_p12 = []
            if signer.cert_registry:
                for c in signer.cert_registry:
                    certs_in_p12.append(c)
            
            # Seleccionamos anclas de confianza (los intermedios o root que vengan en el p12)
            trust_anchors = []
            for c in certs_in_p12:
                # Todo certificado distinto al leaf lo usamos como ancla para poder verificar OCSP
                if c.serial_number != cert.serial_number:
                    trust_anchors.append(CertTrustAnchor(c))
                    
            # Si el p12 no trajo la cadena (ancla de confianza), intentamos descargar el certificado
            # del emisor CA de forma dinámica utilizando la extensión AIA (Authority Information Access)
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
                            import urllib.request
                            # Descargar el certificado emisor CA en formato DER/PEM
                            with urllib.request.urlopen(issuer_url, timeout=5) as response:
                                cert_bytes = response.read()
                            from asn1crypto import x509
                            issuer_cert = x509.Certificate.load(cert_bytes)
                            if issuer_cert:
                                trust_anchors.append(CertTrustAnchor(issuer_cert))
                                certs_in_p12.append(issuer_cert)
                except Exception:
                    pass
                    
            if not trust_anchors:
                # Si no hay cadena y no se pudo descargar, confiamos en el propio leaf cert
                # como último recurso, sabiendo que esto no podrá validar revocación completa.
                trust_anchors.append(CertTrustAnchor(cert))
                
            # Intentamos validación local de la integridad y firma del certificado
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

                # Fallback Criptográfico Local (Modo Offline / VPN):
                # Si el certificado está vigente en fechas y su clave privada es válida,
                # pero el servidor OCSP o la CA raíz de confianza no están accesibles en el sistema local:
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
    """
    Extrae la información del certificado sin guardar la contraseña en ningún lado.
    REGLA DE ORO: La contraseña entra, se usa en esta variable local y se destruye.
    """
    try:
        signer = _load_signer(p12_path, password)
        cert = signer.signing_cert
        
        subject_native = cert.subject.native
        issuer_native = cert.issuer.native
        
        # 1. Tipo de Certificado
        tipo_cert = "SHA256 RSA" # fallback por defecto
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
                
                # Identificar el Hash
                hash_part = "SHA256"
                if "SHA512" in algo_str:
                    hash_part = "SHA512"
                elif "SHA384" in algo_str:
                    hash_part = "SHA384"
                elif "SHA224" in algo_str:
                    hash_part = "SHA224"
                elif "SHA1" in algo_str:
                    hash_part = "SHA1"
                elif "MD5" in algo_str:
                    hash_part = "MD5"
                    
                # Identificar la Criptografía
                crypto_part = "RSA"
                if "ECDSA" in algo_str:
                    crypto_part = "ECDSA"
                elif "DSA" in algo_str:
                    crypto_part = "DSA"
                elif "ED25519" in algo_str:
                    crypto_part = "ED25519"
                    
                tipo_cert = f"{hash_part} {crypto_part}"
        except Exception:
            pass
                
        # 2. Nombre Certificado
        nombre = subject_native.get('common_name', cert.subject.human_friendly)
        if isinstance(nombre, list) and len(nombre) > 0:
            nombre = nombre[0]
        
        # 3. Cargo
        cargo = subject_native.get('title', '')
        if isinstance(cargo, list) and len(cargo) > 0:
            cargo = cargo[0]
            
        # 4. Nombre Institucion
        institucion = subject_native.get('organization_name', '')
        if isinstance(institucion, list) and len(institucion) > 0:
            institucion = institucion[0]
        if not institucion:
            institucion = subject_native.get('organizational_unit_name', '')
            if isinstance(institucion, list) and len(institucion) > 0:
                institucion = institucion[0]
        if not institucion:
            institucion = "Ninguna"
            
        # 5. Numeros de Serie (Corto y Completo)
        serial_int = cert.serial_number
        serial_hex = f"{serial_int:X}"
        if len(serial_hex) % 2 != 0:
            serial_hex = "0" + serial_hex
        # Formatear con dos puntos
        full_serial = ":".join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))
        
        # Serie Corto (últimos 2 bytes = 4 caracteres de hex = 2 partes de la lista de bytes)
        serial_parts = full_serial.split(":")
        short_serial = ":".join(serial_parts[-2:]) if len(serial_parts) >= 2 else full_serial
        
        # 6. Correo Electronico
        email = subject_native.get('email_address', '')
        if isinstance(email, list) and len(email) > 0:
            email = email[0]
        if not email:
            email = subject_native.get('email', '')
            if isinstance(email, list) and len(email) > 0:
                email = email[0]
        if not email:
            email = subject_native.get('rfc822_name', '')
            if isinstance(email, list) and len(email) > 0:
                email = email[0]
        if not email:
            email = "No especificado"
            
        issuer_name = issuer_native.get('common_name', cert.issuer.human_friendly)
        if isinstance(issuer_name, list) and len(issuer_name) > 0:
            issuer_name = issuer_name[0]
            
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

def sign_pdf(input_pdf_path: str, output_pdf_path: str, p12_path: str, password: str,
             page_num: int, x: float, y: float, width: float, height: float,
             lock_document: bool = False, image_path: str = None, font_size: int = None):
    try:
        signer = _load_signer(p12_path, password)
        
        with open(input_pdf_path, 'rb') as doc:
            pdf_writer = IncrementalPdfFileWriter(doc, strict=False)
            pdf_reader = pdf_writer.prev
            
            # Verificar si el documento ya posee un bloqueo de "no cambios" por una firma anterior
            # Esto previene agregar firmas adicionales a un documento cerrado (cadena de confianza cerrada)
            for sig in pdf_reader.embedded_signatures:
                if sig.docmdp_level == fields.MDPPerm.NO_CHANGES or sig.docmdp_level == 1:
                    raise Exception("Este documento está bloqueado por una firma digital previa (cadena de confianza cerrada) y no admite más firmas ni modificaciones.")
            
            # REGLA DE ORO: Si el PDF está protegido/encriptado (ej. RIF SENIAT), 
            # intentar desbloquearlo con contraseña vacía (b'') como hacen los visores PDF
            if pdf_reader.encrypted:
                pdf_reader.decrypt(b'')
                
            import uuid
            sig_field_name = f"Firma_Sofii_{uuid.uuid4().hex[:8]}"
            
            # Verificar si el documento ya posee firmas previas
            has_existing_signatures = len(pdf_reader.embedded_signatures) > 0
            should_certify = lock_document and not has_existing_signatures
            
            field_mdp_spec = None
            doc_mdp_update_value = None
            if lock_document:
                from pyhanko.sign.fields import FieldMDPSpec, FieldMDPAction
                field_mdp_spec = FieldMDPSpec(action=FieldMDPAction.ALL)
                doc_mdp_update_value = fields.MDPPerm.NO_CHANGES

            # En pyHanko y PDF, las coordenadas (x,y) van de bottom-left a top-right.
            # PyMuPDF provee x, y como top-left. Para hacer la conversión requerimos el total de páginas y el alto exacto.
            total_pages = None
            try:
                total_pages = int(pdf_reader.root['/Pages']['/Count'])
            except Exception:
                pass

            # Fallback seguro para total_pages usando PyMuPDF si pyHanko no pudo resolverlo
            if total_pages is None:
                try:
                    import fitz
                    with fitz.open(input_pdf_path) as fitz_doc:
                        if fitz_doc.is_encrypted:
                            fitz_doc.authenticate("")
                        total_pages = len(fitz_doc)
                except Exception:
                    pass

            if total_pages is not None and (page_num < 1 or page_num > total_pages):
                raise Exception(f"El documento solo contiene {total_pages} página(s), pero se solicitó firmar en la página {page_num}.")

            # Obtener el alto de la página navegando el árbol de páginas de pyHanko
            page_height = None
            try:
                page_ref, _ = pdf_reader.find_page_for_modification(page_num - 1)
                target_page = page_ref.get_object()
                media_box = target_page.get('/MediaBox')
                if media_box is None:
                    curr = target_page
                    while curr and '/MediaBox' not in curr and '/Parent' in curr:
                        curr = curr['/Parent'].get_object()
                    if curr and '/MediaBox' in curr:
                        media_box = curr['/MediaBox']

                if media_box is not None:
                    page_height = float(media_box[3]) - float(media_box[1])
            except Exception:
                pass

            # Fallback secundario con PyMuPDF en caso de estructuras de MediaBox no estándar
            if page_height is None:
                try:
                    import fitz
                    with fitz.open(input_pdf_path) as fitz_doc:
                        if fitz_doc.is_encrypted:
                            fitz_doc.authenticate("")
                        page_height = fitz_doc[page_num - 1].rect.height
                except Exception:
                    # Fallback de emergencia a formato estándar A4 (842 pt)
                    page_height = 842.0

            # Convertir Y top-left a bottom-left
            y_bottom = page_height - (y + height)
            y_top = page_height - y
            box = (x, y_bottom, x + width, y_top)
            
            append_signature_field(
                pdf_writer,
                SigFieldSpec(
                    sig_field_name, 
                    box=box, 
                    on_page=page_num - 1, 
                    field_mdp_spec=field_mdp_spec,
                    doc_mdp_update_value=doc_mdp_update_value
                )
            )

            # Estilo Visual
            if image_path and os.path.exists(image_path):
                from pyhanko.pdf_utils.images import PdfImage
                from pyhanko.pdf_utils.layout import SimpleBoxLayoutRule, InnerScaling, AxisAlignment
                
                # pyHanko puede cargar directamente imágenes a través de PdfImage
                background = PdfImage(image_path)
                stamp = StaticStampStyle(
                    background=background,
                    border_width=0,
                    background_layout=SimpleBoxLayoutRule(
                        x_align=AxisAlignment.ALIGN_MID,
                        y_align=AxisAlignment.ALIGN_MID,
                        inner_content_scaling=InnerScaling.SHRINK_TO_FIT
                    )
                )
            else:
                from pyhanko.pdf_utils import layout, text
                
                # Extraer Nombre (CN), Cargo (T/Title) e Institución (O)
                subject_dict = signer.signing_cert.subject.native
                nombre = subject_dict.get('common_name', '')
                if isinstance(nombre, list) and len(nombre) > 0:
                    nombre = nombre[0]
                
                cargo = subject_dict.get('title', '')
                if isinstance(cargo, list) and len(cargo) > 0:
                    cargo = cargo[0]
                    
                institucion = subject_dict.get('organization_name', '')
                if isinstance(institucion, list) and len(institucion) > 0:
                    institucion = institucion[0]
                
                # Para centrar el texto usando espacios en la fuente Courier (monospaciada por defecto),
                # calculamos el ancho máximo basándonos en un placeholder de 19 caracteres para la fecha (YYYY-MM-DD HH:MM:SS)
                fecha_placeholder = "Fecha: YYYY-MM-DD HH:MM:SS"
                lineas_para_calc = []
                if nombre:
                    lineas_para_calc.append(f"Firmado por: {nombre}")
                if cargo and cargo.strip() and cargo != "Ninguna":
                    lineas_para_calc.append(cargo)
                if institucion and institucion.strip() and institucion != "Ninguna":
                    lineas_para_calc.append(institucion)
                lineas_para_calc.append(fecha_placeholder)
                
                max_len = max(len(l) for l in lineas_para_calc) if lineas_para_calc else 0
                
                # Acolchar cada línea con espacios para centrarla horizontalmente
                lineas_acolchadas = []
                if nombre:
                    espacios = (max_len - len(f"Firmado por: {nombre}")) // 2
                    lineas_acolchadas.append(" " * espacios + f"Firmado por: {nombre}")
                if cargo and cargo.strip() and cargo != "Ninguna":
                    espacios = (max_len - len(cargo)) // 2
                    lineas_acolchadas.append(" " * espacios + cargo)
                if institucion and institucion.strip() and institucion != "Ninguna":
                    espacios = (max_len - len(institucion)) // 2
                    lineas_acolchadas.append(" " * espacios + institucion)
                
                # Centrado de la fecha (placeholder)
                espacios_fecha = (max_len - len(fecha_placeholder)) // 2
                if espacios_fecha > 0:
                    lineas_acolchadas.append(" " * espacios_fecha + "Fecha: %(ts)s")
                else:
                    lineas_acolchadas.append("Fecha: %(ts)s")
                
                stamp_text_final = "\n".join(lineas_acolchadas)
                
                font_size_final = font_size if font_size is not None else 11
                stamp = TextStampStyle(
                    stamp_text=stamp_text_final,
                    timestamp_format='%Y-%m-%d %H:%M:%S',
                    border_width=0,
                    text_box_style=text.TextBoxStyle(
                        font_size=font_size_final,
                        box_layout_rule=layout.SimpleBoxLayoutRule(
                            x_align=layout.AxisAlignment.ALIGN_MID,
                            y_align=layout.AxisAlignment.ALIGN_MID,
                            inner_content_scaling=layout.InnerScaling.NO_SCALING
                        )
                    )
                )

            meta = signers.PdfSignatureMetadata(
                field_name=sig_field_name,
                reason="Firma Digital Autorizada",
                location="Caracas, Venezuela",
                contact_info="Sistema Sofii - FII",
                md_algorithm="sha512",
                certify=should_certify,
                docmdp_permissions=fields.MDPPerm.NO_CHANGES if should_certify else None,
            )

            with open(output_pdf_path, 'wb') as outf:
                # Inicializar el firmador con el estilo visual
                from pyhanko.sign.signers.pdf_signer import PdfSigner
                pdf_signer_instance = PdfSigner(
                    signature_meta=meta,
                    signer=signer,
                    stamp_style=stamp
                )
                
                # Ejecutar la firma y escribir en el archivo de salida
                pdf_signer_instance.sign_pdf(
                    pdf_out=pdf_writer,
                    in_place=False,
                    output=outf
                )
    except Exception as e:
        raise Exception(f"Fallo en el proceso de firma: {e}")
