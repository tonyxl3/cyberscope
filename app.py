#!/usr/bin/env python3

import os
import json
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import threading
import time

# Importar módulos de CyberScope
from cyberscope.core.forensics import (
    hash_file, extraer_exif, extraer_pdf_meta, extraer_iocs
)
from cyberscope.core.webscan import (
    analizar_pagina_web, dirscan, login_check
)
from cyberscope.core.osint import whois_lookup, ip_lookup
from cyberscope.core.pentesting import (
    escanear_puertos, detectar_vulnerabilidades_web,
    analizar_certificado_ssl, fuzzing_parametros_web,
    escaneo_completo_pentesting
)
from cyberscope.core.report import exportar_json, generar_reporte_pdf
from cyberscope.core.utils import FINDINGS, logger
from cyberscope.core.chatgpt_analyzer import CyberScopeAnalyzer
from cyberscope.core.pdf_generator import CyberScopePDFGenerator
from cyberscope.core.remote_scanner import RemoteForensicScanner
from cyberscope.core.remote_config import RemoteForensicConfig
from cyberscope.core.remote_key_manager import ensure_ssh_key_and_push

app = Flask(__name__)
app.secret_key = 'cyberscope-secret-key-2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REPORTS_FOLDER'] = 'reports'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Crear directorios necesarios
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

# Almacenamiento en memoria para análisis en progreso
analysis_status = {}

# Configuración de Groq API (GRATUITA)
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '').strip()  # Variable de entorno para Groq

# Validar API key
if GROQ_API_KEY and not GROQ_API_KEY.startswith('gsk_'):
    logger.warning(f"⚠️ GROQ_API_KEY parece inválida: {GROQ_API_KEY[:10]}...")
    GROQ_API_KEY = None

if GROQ_API_KEY:
    logger.info("🚀 Groq API configurada - Análisis IA disponible")
    logger.info(f"   API Key: {GROQ_API_KEY[:10]}...{GROQ_API_KEY[-4:]}")
else:
    logger.info("ℹ️ Groq API no configurada - Usando analizador inteligente")
    logger.info("   Para habilitar: export GROQ_API_KEY=gsk_tu_api_key")

# Inicializar analizador principal
analyzer = CyberScopeAnalyzer(GROQ_API_KEY)

def clear_findings():
    """Limpiar hallazgos anteriores"""
    global FINDINGS
    FINDINGS.clear()

def generate_report_id():
    """Generar ID único para el reporte"""
    return str(uuid.uuid4())[:8]

def analyze_urls_background(urls, report_id, analysis_types):
    """Ejecutar análisis en background"""
    try:
        analysis_status[report_id]['status'] = 'running'
        analysis_status[report_id]['progress'] = 0
        
        clear_findings()
        
        total_urls = len(urls)
        
        for i, url in enumerate(urls):
            if analysis_status[report_id]['status'] == 'cancelled':
                break
                
            url = url.strip()
            if not url:
                continue
                
            analysis_status[report_id]['current_url'] = url
            analysis_status[report_id]['progress'] = int((i / total_urls) * 80)  # 80% para escaneo
            
            # Análisis web básico
            if 'webscan' in analysis_types:
                analizar_pagina_web(url)
            
            # Detección de vulnerabilidades
            if 'vulnscan' in analysis_types:
                detectar_vulnerabilidades_web(url)
            
            # Análisis SSL
            if 'sslcheck' in analysis_types:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    if parsed.scheme == 'https':
                        analizar_certificado_ssl(parsed.hostname)
                except:
                    pass
            
            # Fuzzing de parámetros
            if 'paramfuzz' in analysis_types:
                fuzzing_parametros_web(url)
            
            # WHOIS lookup
            if 'whois' in analysis_types:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    if parsed.hostname:
                        whois_lookup(parsed.hostname)
                except:
                    pass
            
            # Escaneo de puertos
            if 'portscan' in analysis_types:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    if parsed.hostname:
                        escanear_puertos(parsed.hostname)
                except:
                    pass
            
            time.sleep(1)  # Pausa entre URLs
        
        # Análisis con IA (Groq o Fallback)
        analysis_status[report_id]['progress'] = 85
        analysis_status[report_id]['current_url'] = 'Analizando con IA...'
        
        ai_analysis = None
        try:
            target_info = {
                'url': urls[0] if urls else 'Multiple URLs',
                'analysis_types': analysis_types,
                'timestamp': datetime.now().isoformat()
            }
            
            ai_analysis = analyzer.analyze_findings(FINDINGS, target_info)
            
            if ai_analysis:
                logger.info(f"✅ Análisis IA completado con {ai_analysis.get('analyzer', 'analizador')}")
            else:
                logger.warning("⚠️ No se pudo completar análisis IA")
                
        except Exception as e:
            logger.error(f"❌ Error en análisis IA: {e}")
            FINDINGS.append(f"[AI_ERROR] Error en análisis IA: {str(e)}")

        # Generar reportes
        analysis_status[report_id]['progress'] = 90
        analysis_status[report_id]['current_url'] = 'Generando reportes...'
        
        # Preparar datos completos para el reporte
        complete_analysis_data = {
            'target_info': {
                'url': urls[0] if urls else 'Multiple URLs',
                'analysis_types': analysis_types,
                'timestamp': datetime.now().isoformat(),
                'total_urls': len(urls)
            },
            'findings': FINDINGS.copy(),
            'chatgpt_analysis': ai_analysis  # Mantener nombre para compatibilidad
        }
        
        # Exportar JSON
        json_filename = f"reporte_{report_id}.json"
        json_path = os.path.join(app.config['REPORTS_FOLDER'], json_filename)
        
        # Guardar análisis completo en JSON
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(complete_analysis_data, f, indent=2, ensure_ascii=False)
        
        # Generar PDF mejorado
        pdf_filename = f"reporte_{report_id}.pdf"
        pdf_path = os.path.join(app.config['REPORTS_FOLDER'], pdf_filename)
        
        try:
            pdf_generator = CyberScopePDFGenerator()
            pdf_generator.generate_comprehensive_report(complete_analysis_data, pdf_path)
            logger.info(f"📄 PDF generado: {pdf_filename}")
        except Exception as e:
            logger.error(f"❌ Error generando PDF mejorado: {e}")
            # Fallback al generador original
            try:
                generar_reporte_pdf(pdf_path)
                logger.info(f"📄 PDF generado con fallback: {pdf_filename}")
            except Exception as e2:
                logger.error(f"❌ Error en PDF fallback: {e2}")
        
        analysis_status[report_id]['status'] = 'completed'
        analysis_status[report_id]['progress'] = 100
        analysis_status[report_id]['json_file'] = json_filename
        analysis_status[report_id]['pdf_file'] = pdf_filename
        analysis_status[report_id]['findings_count'] = len(FINDINGS)
        analysis_status[report_id]['findings'] = FINDINGS.copy()
        analysis_status[report_id]['chatgpt_analysis'] = ai_analysis
        
        logger.info(f"🎉 Análisis completado: {report_id}")
        
    except Exception as e:
        analysis_status[report_id]['status'] = 'error'
        analysis_status[report_id]['error'] = str(e)
        logger.error(f"💥 Error en análisis background: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        urls_text = data.get('urls', '').strip()
        analysis_types = data.get('analysis_types', [])
        
        if not urls_text:
            return jsonify({'error': 'No se proporcionaron URLs'}), 400
        
        if not analysis_types:
            return jsonify({'error': 'Selecciona al menos un tipo de análisis'}), 400
        
        # Procesar URLs
        urls = [url.strip() for url in urls_text.split('\n') if url.strip()]
        
        if not urls:
            return jsonify({'error': 'No se encontraron URLs válidas'}), 400
        
        # Validar URLs básicamente
        valid_urls = []
        for url in urls:
            if url.startswith(('http://', 'https://', 'ftp://')) or '.' in url:
                valid_urls.append(url)
        
        if not valid_urls:
            return jsonify({'error': 'No se encontraron URLs válidas (deben incluir protocolo o dominio)'}), 400
        
        # Generar ID del reporte
        report_id = generate_report_id()
        
        # Inicializar estado del análisis
        analysis_status[report_id] = {
            'status': 'starting',
            'progress': 0,
            'current_url': '',
            'urls_count': len(valid_urls),
            'analysis_types': analysis_types,
            'started_at': datetime.now().isoformat()
        }
        
        # Iniciar análisis en background
        thread = threading.Thread(
            target=analyze_urls_background,
            args=(valid_urls, report_id, analysis_types)
        )
        thread.daemon = True
        thread.start()
        
        logger.info(f"🚀 Análisis iniciado: {report_id} para {len(valid_urls)} URLs")
        
        return jsonify({
            'report_id': report_id,
            'message': 'Análisis iniciado correctamente',
            'urls_count': len(valid_urls)
        })
        
    except Exception as e:
        logger.error(f"💥 Error iniciando análisis: {e}")
        return jsonify({'error': f'Error iniciando análisis: {str(e)}'}), 500

@app.route('/status/<report_id>')
def get_status(report_id):
    if report_id not in analysis_status:
        return jsonify({'error': 'Reporte no encontrado'}), 404
    
    status = analysis_status[report_id].copy()
    
    # Agregar información adicional si está disponible
    if status.get('status') == 'completed' and status.get('chatgpt_analysis'):
        ai_analysis = status['chatgpt_analysis']
        status['ai_summary'] = {
            'risk_level': ai_analysis.get('risk_level', 'N/A'),
            'executive_summary': ai_analysis.get('executive_summary', ''),
            'analyzer_used': ai_analysis.get('analyzer', 'Analizador Inteligente')
        }
    
    return jsonify(status)

@app.route('/cancel/<report_id>', methods=['POST'])
def cancel_analysis(report_id):
    if report_id not in analysis_status:
        return jsonify({'error': 'Reporte no encontrado'}), 404
    
    analysis_status[report_id]['status'] = 'cancelled'
    logger.info(f"🛑 Análisis cancelado: {report_id}")
    return jsonify({'message': 'Análisis cancelado'})

@app.route('/download/<report_id>/<file_type>')
def download_report(report_id, file_type):
    if report_id not in analysis_status:
        return jsonify({'error': 'Reporte no encontrado'}), 404
    
    status = analysis_status[report_id]
    
    if status['status'] != 'completed':
        return jsonify({'error': 'El análisis no ha terminado'}), 400
    
    if file_type == 'json':
        filename = status.get('json_file')
    elif file_type == 'pdf':
        filename = status.get('pdf_file')
    else:
        return jsonify({'error': 'Tipo de archivo no válido'}), 400
    
    if not filename:
        return jsonify({'error': 'Archivo no disponible'}), 404
    
    file_path = os.path.join(app.config['REPORTS_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'Archivo no encontrado'}), 404
    
    logger.info(f"📥 Descargando: {filename}")
    return send_file(file_path, as_attachment=True)

@app.route('/forensics')
def forensics():
    return render_template('forensics.html')

@app.route('/upload_file', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No se seleccionó archivo'}), 400
        
        file = request.files['file']
        analysis_type = request.form.get('analysis_type')
        
        if file.filename == '':
            return jsonify({'error': 'No se seleccionó archivo'}), 400
        
        if not analysis_type:
            return jsonify({'error': 'Selecciona un tipo de análisis'}), 400
        
        # Guardar archivo
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        clear_findings()
        
        logger.info(f"🔍 Iniciando análisis forense: {filename} ({analysis_type})")
        
        # Realizar análisis según el tipo
        if analysis_type == 'hash':
            hash_file(file_path)
        elif analysis_type == 'exif':
            extraer_exif(file_path)
        elif analysis_type == 'pdf':
            extraer_pdf_meta(file_path)
        elif analysis_type == 'ioc':
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                extraer_iocs(content)
        
        # Análisis con IA para archivos forenses
        ai_analysis = None
        try:
            target_info = {
                'url': f'Archivo: {filename}',
                'analysis_types': [analysis_type],
                'timestamp': datetime.now().isoformat()
            }
            
            ai_analysis = analyzer.analyze_findings(FINDINGS, target_info)
            
            if ai_analysis:
                logger.info(f"✅ Análisis IA forense completado con {ai_analysis.get('analyzer', 'analizador')}")
                
        except Exception as e:
            logger.error(f"❌ Error en análisis IA forense: {e}")
        
        # Generar reporte
        report_id = generate_report_id()
        
        # Datos completos del análisis forense
        complete_analysis_data = {
            'target_info': {
                'url': f'Archivo: {filename}',
                'analysis_types': [analysis_type],
                'timestamp': datetime.now().isoformat(),
                'file_type': 'forensic_file'
            },
            'findings': FINDINGS.copy(),
            'chatgpt_analysis': ai_analysis  # Mantener nombre para compatibilidad
        }
        
        # Exportar resultados
        json_filename = f"forensics_{report_id}.json"
        json_path = os.path.join(app.config['REPORTS_FOLDER'], json_filename)
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(complete_analysis_data, f, indent=2, ensure_ascii=False)
        
        pdf_filename = f"forensics_{report_id}.pdf"
        pdf_path = os.path.join(app.config['REPORTS_FOLDER'], pdf_filename)
        
        try:
            pdf_generator = CyberScopePDFGenerator()
            pdf_generator.generate_comprehensive_report(complete_analysis_data, pdf_path)
            logger.info(f"📄 PDF forense generado: {pdf_filename}")
        except Exception as e:
            logger.error(f"❌ Error generando PDF forense: {e}")
            try:
                generar_reporte_pdf(pdf_path)
                logger.info(f"📄 PDF forense generado con fallback: {pdf_filename}")
            except Exception as e2:
                logger.error(f"❌ Error en PDF forense fallback: {e2}")
        
        # Registrar el reporte en analysis_status para permitir descarga
        analysis_status[report_id] = {
            'status': 'completed',
            'progress': 100,
            'json_file': json_filename,
            'pdf_file': pdf_filename,
            'findings_count': len(FINDINGS),
            'findings': FINDINGS.copy(),
            'chatgpt_analysis': ai_analysis,
            'started_at': datetime.now().isoformat(),
            'analysis_types': [analysis_type],
            'urls_count': 1
        }
        
        # Limpiar archivo subido
        try:
            os.remove(file_path)
        except:
            pass
        
        logger.info(f"🎉 Análisis forense completado: {report_id}")
        
        return jsonify({
            'report_id': report_id,
            'findings_count': len(FINDINGS),
            'findings': FINDINGS,
            'json_file': json_filename,
            'pdf_file': pdf_filename,
            'chatgpt_analysis': ai_analysis
        })
        
    except Exception as e:
        logger.error(f"💥 Error en análisis forense: {e}")
        return jsonify({'error': f'Error en análisis: {str(e)}'}), 500

@app.route('/remote')
def remote():
    return render_template('remote.html')

@app.route('/remote_scan', methods=['POST'])
def remote_scan():
    try:
        data = request.get_json()
        hostname = (data.get('hostname') or '').strip()
        username = (data.get('username') or '').strip()
        port = int(data.get('port', 22))
        scan_type = data.get('scan_type', 'standard')

        # Validación más robusta de parámetros iniciales
        if not hostname or not username:
            return jsonify({'error': 'Hostname y username son requeridos'}), 400

        # Limpiar y validar campos de autenticación
        key_file = data.get('key_file')
        if isinstance(key_file, str):
            key_file = key_file.strip()
            if not key_file:
                key_file = None

        password = data.get('password')
        if isinstance(password, str):
            password = password.strip()
            if not password:
                password = None

        # Validar método de autenticación
        if not key_file and not password:
            return jsonify({'error': 'Debe proporcionar clave privada O contraseña SSH'}), 400
        if key_file and password:
            return jsonify({'error': 'Use solo clave privada O contraseña, no ambas'}), 400

        if port < 1 or port > 65535:
            return jsonify({'error': 'Puerto debe estar entre 1 y 65535'}), 400

        valid_scan_types = ['quick', 'standard', 'comprehensive', 'vulnerability']
        if scan_type not in valid_scan_types:
            return jsonify({'error': f'Tipo de escaneo debe ser uno de: {", ".join(valid_scan_types)}'}), 400

        clear_findings()

        # Inicializar configuración
        try:
            config = RemoteForensicConfig().config
        except Exception as e:
            logger.error(f"Error cargando configuración: {e}")
            config = {
                'ssh_timeout': 50,
                'max_concurrent': 3,
                'evidence_dir': './forensic_evidence'
            }

        scanner = RemoteForensicScanner(config)

        logger.info(f"🔗 Iniciando análisis remoto: {hostname}:{port} como {username} (tipo: {scan_type})")
        FINDINGS.append(f"[REMOTE_INIT] Iniciando análisis {scan_type} de {hostname}:{port}")

        if password and not key_file:  
            logger.info("🔐 Instalando clave SSH automática usando sshpass...")
            from cyberscope.core.remote_key_manager import ensure_ssh_key_and_push
            installed = ensure_ssh_key_and_push(hostname, username, password, port)
            if not installed:
                logger.warning("⚠️ No se pudo instalar la clave SSH automáticamente")
        
        if not scanner.test_ssh_connection(hostname, username, key_file, port, password):
            error_msg = f"No se pudo establecer conexión SSH con {hostname}:{port}"
            logger.error(error_msg)
            FINDINGS.append(f"[SSH_CONNECTION_FAILED] {error_msg}")
            return jsonify({'error': error_msg}), 400

        # Ejecutar análisis
        evidence = {}
        vulnerabilities = {}
        try:
            if scan_type == 'quick':
                evidence = scanner.quick_scan(hostname, username, key_file, port, password)
            elif scan_type == 'vulnerability':
                vulnerabilities = scanner.vulnerability_assessment(hostname, username, key_file, port, password)
            elif scan_type == 'comprehensive':
                evidence = scanner.comprehensive_system_analysis(hostname, username, key_file, port, password)
                vulnerabilities = scanner.vulnerability_assessment(hostname, username, key_file, port, password)
            else:  # standard
                evidence = scanner.comprehensive_system_analysis(hostname, username, key_file, port, password)

        except Exception as e:
            error_msg = f"Error durante el análisis remoto: {str(e)}"
            logger.error(error_msg)
            FINDINGS.append(f"[REMOTE_ERROR] {error_msg}")
            return jsonify({'error': error_msg}), 500

        # Análisis IA para escaneo remoto
        ai_analysis = None
        try:
            target_info = {
                'url': f'SSH://{hostname}:{port}',
                'analysis_types': [scan_type],
                'timestamp': datetime.now().isoformat(),
                'scan_type': 'remote_ssh'
            }

            ai_analysis = analyzer.analyze_findings(FINDINGS, target_info)
            
            if ai_analysis:
                logger.info(f"✅ Análisis IA remoto completado con {ai_analysis.get('analyzer', 'analizador')}")

        except Exception as e:
            logger.error(f"❌ Error en análisis IA remoto: {e}")
            FINDINGS.append(f"[AI_ERROR] Error en análisis IA: {str(e)}")

        # Generar reporte
        report_id = generate_report_id()
        evidence_count = len(evidence)
        vuln_count = sum(len(v.get('vulnerabilities_found', [])) for v in vulnerabilities.values())

        complete_analysis_data = {
            'target_info': target_info,
            'findings': FINDINGS.copy(),
            'evidence': evidence,
            'vulnerabilities': vulnerabilities,
            'chatgpt_analysis': ai_analysis,  # Mantener nombre para compatibilidad
            'scanner_session': scanner.session_id,
            'statistics': {
                'evidence_items': evidence_count,
                'vulnerabilities_found': vuln_count,
                'scan_type': scan_type,
                'target': f"{hostname}:{port}"
            }
        }

        try:
            json_filename = f"remote_scan_{report_id}.json"
            with open(os.path.join(app.config['REPORTS_FOLDER'], json_filename), 'w', encoding='utf-8') as f:
                json.dump(complete_analysis_data, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            logger.error(f"❌ Error guardando JSON: {e}")

        try:
            pdf_filename = f"remote_scan_{report_id}.pdf"
            pdf_path = os.path.join(app.config['REPORTS_FOLDER'], pdf_filename)
            CyberScopePDFGenerator().generate_comprehensive_report(complete_analysis_data, pdf_path)
            logger.info(f"📄 PDF remoto generado: {pdf_filename}")
        except Exception as e:
            logger.error(f"❌ Error generando PDF remoto: {e}")
            FINDINGS.append(f"[PDF_ERROR] Error generando PDF: {str(e)}")

        try:
            evidence_chain_file = scanner.export_evidence_chain(
                os.path.join(app.config['REPORTS_FOLDER'], f"evidence_chain_{report_id}.json")
            )
        except Exception as e:
            logger.error(f"❌ Error exportando cadena de evidencia: {e}")
            evidence_chain_file = None

        # Registrar el reporte en analysis_status para permitir descarga
        analysis_status[report_id] = {
            'status': 'completed',
            'progress': 100,
            'json_file': json_filename,
            'pdf_file': pdf_filename,
            'findings_count': len(FINDINGS),
            'findings': FINDINGS.copy(),
            'chatgpt_analysis': ai_analysis,
            'started_at': datetime.now().isoformat(),
            'analysis_types': [scan_type],
            'urls_count': 1,
            'evidence_count': evidence_count,
            'vulnerabilities_count': vuln_count,
            'scanner_session': scanner.session_id
        }
        
        response_data = {
            'report_id': report_id,
            'findings_count': len(FINDINGS),
            'findings': FINDINGS,
            'evidence_count': evidence_count,
            'vulnerabilities_count': vuln_count,
            'json_file': json_filename,
            'pdf_file': pdf_filename,
            'chatgpt_analysis': ai_analysis,
            'scan_type': scan_type,
            'target': f"{hostname}:{port}",
            'scanner_session': scanner.session_id
        }

        if evidence_chain_file:
            response_data['evidence_chain_file'] = os.path.basename(evidence_chain_file)

        logger.info(f"🎉 Análisis remoto completado exitosamente: {hostname}:{port}")
        return jsonify(response_data)

    except ValueError as e:
        logger.error(f"❌ Error de validación: {str(e)}")
        return jsonify({'error': f'Error de validación: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"💥 Error inesperado en análisis remoto: {str(e)}")
        FINDINGS.append(f"[REMOTE_CRITICAL_ERROR] {str(e)}")
        return jsonify({'error': f'Error inesperado: {str(e)}'}), 500

@app.route('/reports')
def reports():
    """Página para ver reportes generados"""
    reports = []
    
    for report_id, status in analysis_status.items():
        if status['status'] == 'completed':
            # Determinar el tipo de análisis basado en los archivos
            json_file = status.get('json_file', '')
            analysis_type = 'Web'
            if json_file.startswith('forensics_'):
                analysis_type = 'Forense'
            elif json_file.startswith('remote_scan_'):
                analysis_type = 'Remoto SSH'
            
            # Agregar información del análisis IA si está disponible
            ai_info = {}
            if status.get('chatgpt_analysis'):
                ai_analysis = status['chatgpt_analysis']
                ai_info = {
                    'risk_level': ai_analysis.get('risk_level', 'N/A'),
                    'analyzer': ai_analysis.get('analyzer', 'N/A')
                }
            
            reports.append({
                'id': report_id,
                'started_at': status.get('started_at'),
                'urls_count': status.get('urls_count', 0),
                'findings_count': status.get('findings_count', 0),
                'analysis_types': status.get('analysis_types', []),
                'has_chatgpt_analysis': bool(status.get('chatgpt_analysis')),
                'analysis_type': analysis_type,
                'evidence_count': status.get('evidence_count', 0),
                'vulnerabilities_count': status.get('vulnerabilities_count', 0),
                'ai_info': ai_info
            })
    
    # Ordenar reportes por fecha (más recientes primero)
    reports.sort(key=lambda x: x.get('started_at', ''), reverse=True)
    
    return render_template('reports.html', reports=reports)

@app.route('/health')
def health():
    """Endpoint de salud para Docker"""
    health_info = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'analyzer': {
            'groq_available': bool(GROQ_API_KEY),
            'fallback_available': True
        },
        'active_analyses': len([s for s in analysis_status.values() if s.get('status') == 'running'])
    }
    return jsonify(health_info)

@app.route('/api/groq/test', methods=['POST'])
def test_groq_connection():
    """Endpoint para probar la conexión con Groq API"""
    try:
        if not GROQ_API_KEY:
            return jsonify({
                'status': 'error',
                'message': 'API key de Groq no configurada',
                'help': 'Configura GROQ_API_KEY en variables de entorno'
            }), 400
        
        if not GROQ_API_KEY.startswith('gsk_'):
            return jsonify({
                'status': 'error',
                'message': 'API key de Groq inválida (debe empezar con gsk_)',
                'current_key_preview': f"{GROQ_API_KEY[:10]}..."
            }), 400
        
        # Crear un analizador temporal para prueba
        test_analyzer = CyberScopeAnalyzer(GROQ_API_KEY)
        
        # Probar con hallazgos de ejemplo
        test_findings = [
            "[TEST] Puerto 80 abierto en servidor web",
            "[TEST] Certificado SSL válido encontrado",
            "[TEST] Servidor Apache versión 2.4.41"
        ]
        
        test_target = {
            'url': 'test.example.com',
            'analysis_types': ['test'],
            'timestamp': datetime.now().isoformat()
        }
        
        result = test_analyzer.analyze_findings(test_findings, test_target)
        
        if result:
            return jsonify({
                'status': 'success',
                'message': 'Conexión con Groq API exitosa',
                'analyzer': result.get('analyzer', 'Groq'),
                'test_summary': result.get('executive_summary', '')[:100] + '...',
                'api_key_preview': f"{GROQ_API_KEY[:10]}...{GROQ_API_KEY[-4:]}"
            })
        else:
            return jsonify({
                'status': 'warning',
                'message': 'Groq no disponible, usando analizador inteligente',
                'fallback': True
            })
            
    except Exception as e:
        logger.error(f"Error probando Groq: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Error probando conexión: {str(e)}',
            'error_details': str(e)
        }), 500

if __name__ == '__main__':
    # Mostrar información de configuración al inicio
    print("\n" + "="*60)
    print("🚀 CyberScope v2.0 - Iniciando...")
    print("="*60)
    
    if GROQ_API_KEY:
        print("✅ Groq API configurada - Análisis IA disponible")
        print("   Modelo: Llama-3.1-70B Versatile (GRATIS)")
        print(f"   API Key: {GROQ_API_KEY[:10]}...{GROQ_API_KEY[-4:]}")
        
        # Test rápido de Groq al inicio
        try:
            test_analyzer = CyberScopeAnalyzer(GROQ_API_KEY)
            if test_analyzer.groq_analyzer and test_analyzer.groq_analyzer.available:
                print("🧪 Test de Groq: ✅ Conexión exitosa")
            else:
                print("🧪 Test de Groq: ⚠️ Configuración incorrecta")
        except Exception as e:
            print(f"🧪 Test de Groq: ❌ Error - {e}")
    else:
        print("ℹ️  Groq API no configurada")
        print("   Usando: Analizador Inteligente de respaldo")
        print("   Para habilitar Groq:")
        print("     1. Ve a: https://console.groq.com")
        print("     2. Crea una API key gratuita")
        print("     3. export GROQ_API_KEY=gsk_tu_api_key")
    
    print(f"📁 Carpeta de reportes: {app.config['REPORTS_FOLDER']}")
    print(f"📁 Carpeta de uploads: {app.config['UPLOAD_FOLDER']}")
    print("🌐 Servidor iniciando en http://localhost:5000")
    
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
