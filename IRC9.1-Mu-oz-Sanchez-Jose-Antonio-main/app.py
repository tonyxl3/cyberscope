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
        key_file_raw = data.get('key_file')
        key_file = key_file_raw.strip() if key_file_raw else None
        port = int(data.get('port', 22))
        scan_type = data.get('scan_type', 'standard')
        
        # Validación más robusta de parámetros
        if not hostname or not username:
            return jsonify({'error': 'Hostname y username son requeridos'}), 400
        
        if port < 1 or port > 65535:
            return jsonify({'error': 'Puerto debe estar entre 1 y 65535'}), 400
        
        # Validar tipos de escaneo
        valid_scan_types = ['quick', 'standard', 'comprehensive', 'vulnerability']
        if scan_type not in valid_scan_types:
            return jsonify({'error': f'Tipo de escaneo debe ser uno de: {", ".join(valid_scan_types)}'}), 400
        
        clear_findings()
        
        # Inicializar configuración corregida
        try:
            config = RemoteForensicConfig().config
        except Exception as e:
            logger.error(f"Error cargando configuración: {e}")
            # Usar configuración por defecto si falla
            config = {
                'ssh_timeout': 30,
                'max_concurrent': 3,
                'evidence_dir': './forensic_evidence'
            }
        
        # Inicializar scanner remoto con configuración validada
        scanner = RemoteForensicScanner(config)
        
        # Log del intento de conexión
        logger.info(f"Iniciando análisis remoto: {hostname}:{port} como {username} (tipo: {scan_type})")
        FINDINGS.append(f"[REMOTE_INIT] Iniciando análisis {scan_type} de {hostname}:{port}")
        
        # Probar conexión SSH primero
        if not scanner.test_ssh_connection(hostname, username, key_file, port):
            error_msg = f"No se pudo establecer conexión SSH con {hostname}:{port}"
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 400
        
        # Ejecutar análisis según el tipo
        evidence = {}
        vulnerabilities = {}
        
        try:
            if scan_type == 'quick':
                evidence = scanner.quick_scan(hostname, username, key_file, port)
                vulnerabilities = {}
                logger.info(f"Escaneo rápido completado para {hostname}")
                
            elif scan_type == 'vulnerability':
                evidence = {}
                vulnerabilities = scanner.vulnerability_assessment(hostname, username, key_file, port)
                logger.info(f"Evaluación de vulnerabilidades completada para {hostname}")
                
            elif scan_type == 'comprehensive':
                evidence = scanner.comprehensive_system_analysis(hostname, username, key_file, port)
                vulnerabilities = scanner.vulnerability_assessment(hostname, username, key_file, port)
                logger.info(f"Análisis comprehensivo completado para {hostname}")
                
            else:  # standard
                evidence = scanner.comprehensive_system_analysis(hostname, username, key_file, port)
                vulnerabilities = {}
                logger.info(f"Análisis estándar completado para {hostname}")
                
        except Exception as e:
            error_msg = f"Error durante el análisis remoto: {str(e)}"
            logger.error(error_msg)
            FINDINGS.append(f"[REMOTE_ERROR] {error_msg}")
            return jsonify({'error': error_msg}), 500
        
        # Análisis con IA
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
        
        # Calcular estadísticas
        evidence_count = len(evidence)
        vuln_count = 0
        for vuln_data in vulnerabilities.values():
            vuln_count += len(vuln_data.get('vulnerabilities_found', []))
        
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
        
        # Exportar resultados
        json_filename = f"remote_scan_{report_id}.json"
        json_path = os.path.join(app.config['REPORTS_FOLDER'], json_filename)
        
        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(complete_analysis_data, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            logger.error(f"Error guardando JSON: {e}")
        
        pdf_filename = f"remote_scan_{report_id}.pdf"
        pdf_path = os.path.join(app.config['REPORTS_FOLDER'], pdf_filename)
        
        try:
            pdf_generator = CyberScopePDFGenerator()
            pdf_generator.generate_comprehensive_report(complete_analysis_data, pdf_path)
        except Exception as e:
            logger.error(f"Error generando PDF remoto: {e}")
            FINDINGS.append(f"[PDF_ERROR] Error generando PDF: {str(e)}")
        
        # Exportar cadena de evidencia forense
        try:
            evidence_chain_file = scanner.export_evidence_chain(
                os.path.join(app.config['REPORTS_FOLDER'], f"evidence_chain_{report_id}.json")
            )
        except Exception as e:
            logger.error(f"Error exportando cadena de evidencia: {e}")
            evidence_chain_file = None
        
        # Respuesta de éxito
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
        error_msg = f"Error de validación: {str(e)}"
        logger.error(error_msg)
        return jsonify({'error': error_msg}), 400
    except Exception as e:
        error_msg = f"Error inesperado en análisis remoto: {str(e)}"
        logger.error(error_msg)
        FINDINGS.append(f"[REMOTE_CRITICAL_ERROR] {error_msg}")
        return jsonify({'error': error_msg}), 500


@app.route('/reports')
def reports():
    """Página para ver reportes generados"""
    reports = []
    
    for report_id, status in analysis_status.items():
        if status['status'] == 'completed':
            reports.append({
                'id': report_id,
                'started_at': status.get('started_at'),
                'urls_count': status.get('urls_count', 0),
                'findings_count': status.get('findings_count', 0),
                'analysis_types': status.get('analysis_types', []),
                'has_chatgpt_analysis': bool(status.get('chatgpt_analysis'))
            })
    
    return render_template('reports.html', reports=reports)

@app.route('/health')
def health():
    """Endpoint de salud para Docker"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
