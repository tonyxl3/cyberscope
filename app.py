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
from cyberscope.core.chatgpt_analyzer import ChatGPTAnalyzer, ChatGPTFallbackAnalyzer
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

# Configuración de ChatGPT (opcional)
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')  # Variable de entorno opcional
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
            analysis_status[report_id]['progress'] = int((i / total_urls) * 100)
            
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
        
        # Análisis con ChatGPT
        analysis_status[report_id]['progress'] = 85
        analysis_status[report_id]['current_url'] = 'Analizando con IA...'
        
        chatgpt_analysis = None
        try:
            if OPENAI_API_KEY:
                # Usar ChatGPT API
                chatgpt_analyzer = ChatGPTAnalyzer(OPENAI_API_KEY)
                target_info = {
                    'url': urls[0] if urls else 'Multiple URLs',
                    'analysis_types': analysis_types,
                    'timestamp': datetime.now().isoformat()
                }
                chatgpt_analysis = chatgpt_analyzer.analyze_findings_with_chatgpt(FINDINGS, target_info)
            else:
                # Usar análisis de respaldo
                fallback_analyzer = ChatGPTFallbackAnalyzer()
                target_info = {
                    'url': urls[0] if urls else 'Multiple URLs',
                    'analysis_types': analysis_types,
                    'timestamp': datetime.now().isoformat()
                }
                chatgpt_analysis = fallback_analyzer.analyze_findings_with_rules(FINDINGS, target_info)
        except Exception as e:
            logger.error(f"Error en análisis ChatGPT: {e}")
            FINDINGS.append(f"[CHATGPT_ERROR] Error en análisis IA: {str(e)}")
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
            'chatgpt_analysis': chatgpt_analysis
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
        except Exception as e:
            logger.error(f"Error generando PDF mejorado: {e}")
            # Fallback al generador original
            generar_reporte_pdf(pdf_path)
        
        analysis_status[report_id]['status'] = 'completed'
        analysis_status[report_id]['progress'] = 100
        analysis_status[report_id]['json_file'] = json_filename
        analysis_status[report_id]['pdf_file'] = pdf_filename
        analysis_status[report_id]['findings_count'] = len(FINDINGS)
        analysis_status[report_id]['findings'] = FINDINGS.copy()
        analysis_status[report_id]['chatgpt_analysis'] = chatgpt_analysis
        
    except Exception as e:
        analysis_status[report_id]['status'] = 'error'
        analysis_status[report_id]['error'] = str(e)
        logger.error(f"Error en análisis background: {e}")

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
        
        # Generar ID del reporte
        report_id = generate_report_id()
        
        # Inicializar estado del análisis
        analysis_status[report_id] = {
            'status': 'starting',
            'progress': 0,
            'current_url': '',
            'urls_count': len(urls),
            'analysis_types': analysis_types,
            'started_at': datetime.now().isoformat()
        }
        
        # Iniciar análisis en background
        thread = threading.Thread(
            target=analyze_urls_background,
            args=(urls, report_id, analysis_types)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'report_id': report_id,
            'message': 'Análisis iniciado correctamente'
        })
        
    except Exception as e:
        logger.error(f"Error iniciando análisis: {e}")
        return jsonify({'error': f'Error iniciando análisis: {str(e)}'}), 500

@app.route('/status/<report_id>')
def get_status(report_id):
    if report_id not in analysis_status:
        return jsonify({'error': 'Reporte no encontrado'}), 404
    
    return jsonify(analysis_status[report_id])

@app.route('/cancel/<report_id>', methods=['POST'])
def cancel_analysis(report_id):
    if report_id not in analysis_status:
        return jsonify({'error': 'Reporte no encontrado'}), 404
    
    analysis_status[report_id]['status'] = 'cancelled'
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
        chatgpt_analysis = None
        try:
            if OPENAI_API_KEY:
                chatgpt_analyzer = ChatGPTAnalyzer(OPENAI_API_KEY)
                target_info = {
                    'url': f'Archivo: {filename}',
                    'analysis_types': [analysis_type],
                    'timestamp': datetime.now().isoformat()
                }
                chatgpt_analysis = chatgpt_analyzer.analyze_findings_with_chatgpt(FINDINGS, target_info)
            else:
                fallback_analyzer = ChatGPTFallbackAnalyzer()
                target_info = {
                    'url': f'Archivo: {filename}',
                    'analysis_types': [analysis_type],
                    'timestamp': datetime.now().isoformat()
                }
                chatgpt_analysis = fallback_analyzer.analyze_findings_with_rules(FINDINGS, target_info)
        except Exception as e:
            logger.error(f"Error en análisis ChatGPT forense: {e}")
        
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
            'chatgpt_analysis': chatgpt_analysis
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
        except Exception as e:
            logger.error(f"Error generando PDF forense mejorado: {e}")
            generar_reporte_pdf(pdf_path)
        
        # Registrar el reporte en analysis_status para permitir descarga
        analysis_status[report_id] = {
            'status': 'completed',
            'progress': 100,
            'json_file': json_filename,
            'pdf_file': pdf_filename,
            'findings_count': len(FINDINGS),
            'findings': FINDINGS.copy(),
            'chatgpt_analysis': chatgpt_analysis,
            'started_at': datetime.now().isoformat(),
            'analysis_types': [analysis_type],
            'urls_count': 1
        }
        
        # Limpiar archivo subido
        os.remove(file_path)
        
        return jsonify({
            'report_id': report_id,
            'findings_count': len(FINDINGS),
            'findings': FINDINGS,
            'json_file': json_filename,
            'pdf_file': pdf_filename,
            'chatgpt_analysis': chatgpt_analysis
        })
        
    except Exception as e:
        logger.error(f"Error en análisis forense: {e}")
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

        logger.info(f"Iniciando análisis remoto: {hostname}:{port} como {username} (tipo: {scan_type})")
        FINDINGS.append(f"[REMOTE_INIT] Iniciando análisis {scan_type} de {hostname}:{port}")

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

        # Análisis ChatGPT / fallback
        chatgpt_analysis = None
        try:
            target_info = {
                'url': f'SSH://{hostname}:{port}',
                'analysis_types': [scan_type],
                'timestamp': datetime.now().isoformat(),
                'scan_type': 'remote_ssh'
            }

            if OPENAI_API_KEY:
                chatgpt_analyzer = ChatGPTAnalyzer(OPENAI_API_KEY)
                chatgpt_analysis = chatgpt_analyzer.analyze_findings_with_chatgpt(FINDINGS, target_info)
            else:
                fallback_analyzer = ChatGPTFallbackAnalyzer()
                chatgpt_analysis = fallback_analyzer.analyze_findings_with_rules(FINDINGS, target_info)

        except Exception as e:
            logger.error(f"Error en análisis ChatGPT remoto: {e}")
            FINDINGS.append(f"[CHATGPT_ERROR] Error en análisis IA: {str(e)}")

        # Generar reporte
        report_id = generate_report_id()
        evidence_count = len(evidence)
        vuln_count = sum(len(v.get('vulnerabilities_found', [])) for v in vulnerabilities.values())

        complete_analysis_data = {
            'target_info': target_info,
            'findings': FINDINGS.copy(),
            'evidence': evidence,
            'vulnerabilities': vulnerabilities,
            'chatgpt_analysis': chatgpt_analysis,
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
            logger.error(f"Error guardando JSON: {e}")

        try:
            pdf_filename = f"remote_scan_{report_id}.pdf"
            pdf_path = os.path.join(app.config['REPORTS_FOLDER'], pdf_filename)
            CyberScopePDFGenerator().generate_comprehensive_report(complete_analysis_data, pdf_path)
        except Exception as e:
            logger.error(f"Error generando PDF remoto: {e}")
            FINDINGS.append(f"[PDF_ERROR] Error generando PDF: {str(e)}")

        try:
            evidence_chain_file = scanner.export_evidence_chain(
                os.path.join(app.config['REPORTS_FOLDER'], f"evidence_chain_{report_id}.json")
            )
        except Exception as e:
            logger.error(f"Error exportando cadena de evidencia: {e}")
            evidence_chain_file = None

        # Registrar el reporte en analysis_status para permitir descarga
        analysis_status[report_id] = {
            'status': 'completed',
            'progress': 100,
            'json_file': json_filename,
            'pdf_file': pdf_filename,
            'findings_count': len(FINDINGS),
            'findings': FINDINGS.copy(),
            'chatgpt_analysis': chatgpt_analysis,
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
            'chatgpt_analysis': chatgpt_analysis,
            'scan_type': scan_type,
            'target': f"{hostname}:{port}",
            'scanner_session': scanner.session_id
        }

        if evidence_chain_file:
            response_data['evidence_chain_file'] = os.path.basename(evidence_chain_file)

        logger.info(f"Análisis remoto completado exitosamente: {hostname}:{port}")
        return jsonify(response_data)

    except ValueError as e:
        logger.error(f"Error de validación: {str(e)}")
        return jsonify({'error': f'Error de validación: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"Error inesperado en análisis remoto: {str(e)}")
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
            
            reports.append({
                'id': report_id,
                'started_at': status.get('started_at'),
                'urls_count': status.get('urls_count', 0),
                'findings_count': status.get('findings_count', 0),
                'analysis_types': status.get('analysis_types', []),
                'has_chatgpt_analysis': bool(status.get('chatgpt_analysis')),
                'analysis_type': analysis_type,
                'evidence_count': status.get('evidence_count', 0),
                'vulnerabilities_count': status.get('vulnerabilities_count', 0)
            })
    
    # Ordenar reportes por fecha (más recientes primero)
    reports.sort(key=lambda x: x.get('started_at', ''), reverse=True)
    
    return render_template('reports.html', reports=reports)

@app.route('/health')
def health():
    """Endpoint de salud para Docker"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
