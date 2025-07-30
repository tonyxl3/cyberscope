#!/usr/bin/env python3

import argparse
import os
import logging

from .core.utils import FINDINGS, logger
from .core.forensics import (
    hash_file, hash_directory,
    buscar_sospechosos,
    extraer_exif, extraer_pdf_meta,
    extraer_iocs
)
from .core.webscan import (
    analizar_pagina_web,
    dirscan,
    login_check
)
from .core.osint import whois_lookup, ip_lookup
from .core.report import exportar_json, generar_reporte_pdf
from .core.pentesting import (
    escanear_puertos,
    detectar_vulnerabilidades_web,
    analizar_certificado_ssl,
    fuzzing_parametros_web,
    escaneo_completo_pentesting
)
from .core.remote_scanner import RemoteForensicScanner
from .core.remote_config import RemoteForensicConfig
from .core.remote_key_manager import ensure_ssh_key_and_push


def main():
    parser = argparse.ArgumentParser(
        description="CyberScope v2.0 - Herramienta de Análisis Forense, Pentesting y OSINT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
    python main.py --hash archivo.txt
    python main.py --buscar /ruta/directorio --pdf
    python main.py --exif imagen.jpg --json
    python main.py --webscan https://miweb.com --pdf
    python main.py --remotessh --host 192.168.1.100 --user root --password mi_pass --type quick --json --pdf
        """
    )

    # Argumentos principales
    parser.add_argument("--hash", help="Archivo o directorio a hashear")
    parser.add_argument("--buscar", help="Buscar archivos sospechosos en directorio")
    parser.add_argument("--exif", help="Extraer metadatos EXIF de imagen")
    parser.add_argument("--pdfmeta", help="Extraer metadatos de archivo PDF")
    parser.add_argument("--ioc", help="Extraer IoCs de archivo de texto")
    parser.add_argument("--webscan", help="Escanear página web")
    parser.add_argument("--dirscan", nargs=2, metavar=('URL', 'WORDLIST'), help="Fuzzing de rutas")
    parser.add_argument("--logincheck", help="Detectar formularios de login")
    parser.add_argument("--whois", help="Consulta WHOIS de dominio")
    parser.add_argument("--ipinfo", help="Lookup de IP")

    # Argumentos de pentesting
    parser.add_argument("--portscan", help="Escanear puertos de un host")
    parser.add_argument("--vulnscan", help="Detectar vulnerabilidades web en URL")
    parser.add_argument("--sslcheck", help="Analizar certificado SSL de un host")
    parser.add_argument("--paramfuzz", help="Fuzzing de parámetros web en URL")
    parser.add_argument("--pentest", help="Escaneo completo de pentesting")

    # Análisis remoto SSH
    parser.add_argument("--remotessh", action="store_true", help="Ejecutar análisis remoto por SSH")
    parser.add_argument("--host", help="Hostname o IP del servidor remoto")
    parser.add_argument("--user", help="Usuario SSH")
    parser.add_argument("--password", help="Contraseña SSH")
    parser.add_argument("--key", help="Ruta de clave privada SSH")
    parser.add_argument("--port", type=int, default=22, help="Puerto SSH (default: 22)")
    parser.add_argument("--type", choices=['quick', 'standard', 'comprehensive', 'vulnerability'], default='standard',
                        help="Tipo de escaneo remoto")

    # Salida
    parser.add_argument("--pdf", action="store_true", help="Generar reporte PDF")
    parser.add_argument("--json", action="store_true", help="Exportar hallazgos a JSON")
    parser.add_argument("--output", help="Directorio de salida para reportes")

    # Configuración
    parser.add_argument("--verbose", "-v", action="store_true", help="Salida detallada")
    parser.add_argument("--version", action="version", version="CyberScope v2.0")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        os.chdir(args.output)

    # Análisis forense
    if args.hash:
        if os.path.isdir(args.hash):
            logger.info(f"Procesando directorio: {args.hash}")
            hash_directory(args.hash)
        elif os.path.isfile(args.hash):
            logger.info(f"Procesando archivo: {args.hash}")
            hash_file(args.hash)
        else:
            logger.error(f"Ruta no válida: {args.hash}")

    if args.buscar:
        buscar_sospechosos(args.buscar)

    if args.exif:
        extraer_exif(args.exif)

    if args.pdfmeta:
        extraer_pdf_meta(args.pdfmeta)

    if args.ioc:
        try:
            with open(args.ioc, 'r', encoding='utf-8') as f:
                extraer_iocs(f.read())
        except Exception as e:
            msg = f"No se pudo leer archivo {args.ioc}: {e}"
            FINDINGS.append(f"[ERROR] {msg}")
            logger.error(msg)

    # Web y OSINT
    if args.webscan:
        analizar_pagina_web(args.webscan)

    if args.dirscan:
        url, wl = args.dirscan
        dirscan(url, wl)

    if args.logincheck:
        login_check(args.logincheck)

    if args.whois:
        whois_lookup(args.whois)

    if args.ipinfo:
        ip_lookup(args.ipinfo)

    # Pentesting
    if args.portscan:
        escanear_puertos(args.portscan)

    if args.vulnscan:
        detectar_vulnerabilidades_web(args.vulnscan)

    if args.sslcheck:
        analizar_certificado_ssl(args.sslcheck)

    if args.paramfuzz:
        fuzzing_parametros_web(args.paramfuzz)

    if args.pentest:
        escaneo_completo_pentesting(args.pentest)

    # Análisis remoto SSH
    if args.remotessh:
        if not args.host or not args.user:
            logger.error("Debe especificar --host y --user para análisis remoto")
            return

        hostname = args.host.strip()
        username = args.user.strip()
        port = args.port
        key_file = args.key.strip() if args.key else None
        password = args.password.strip() if args.password else None

        if not key_file and not password:
            logger.error("Debe proporcionar --key o --password para autenticación SSH")
            return

        if key_file and password:
            logger.error("Proporcione solo --key o --password, no ambos")
            return

        logger.info(f"🔍 Ejecutando análisis remoto {args.type} en {hostname}:{port} como {username}")

        if password and not key_file:
            logger.info("🔐 Intentando instalar clave SSH automáticamente...")
            success = ensure_ssh_key_and_push(hostname, username, password, port)
            if success:
                key_file = "/root/.ssh/id_rsa"
            else:
                logger.warning("⚠️ No se pudo instalar la clave automáticamente, se continuará con password")

        try:
            config = RemoteForensicConfig().config
        except Exception as e:
            logger.warning(f"⚠️ Error cargando configuración remota: {e}")
            config = {
                'ssh_timeout': 60,
                'max_concurrent': 3,
                'evidence_dir': './forensic_evidence'
            }

        scanner = RemoteForensicScanner(config)

        if not scanner.test_ssh_connection(hostname, username, key_file, port, password):
            logger.error("❌ No se pudo conectar por SSH al host remoto")
            return

        evidence = {}
        vulnerabilities = {}

        try:
            if args.type == "quick":
                evidence = scanner.quick_scan(hostname, username, key_file, port, password)
            elif args.type == "vulnerability":
                vulnerabilities = scanner.vulnerability_assessment(hostname, username, key_file, port, password)
            elif args.type == "comprehensive":
                evidence = scanner.comprehensive_system_analysis(hostname, username, key_file, port, password)
                vulnerabilities = scanner.vulnerability_assessment(hostname, username, key_file, port, password)
            else:  # standard
                evidence = scanner.comprehensive_system_analysis(hostname, username, key_file, port, password)
        except Exception as e:
            logger.error(f"Error durante análisis remoto: {e}")
            return

        FINDINGS.append(f"[REMOTE_SSH_SCAN] Análisis remoto completado en {hostname}:{port}")

    # Reportes
    if args.json:
        exportar_json()

    if args.pdf:
        generar_reporte_pdf()

    # Resumen final
    if FINDINGS:
        print(f"\n[+] Análisis completado: {len(FINDINGS)} hallazgos")
        print(f"[+] Log guardado en: cyberscope.log")
        if args.json:
            print(f"[+] Hallazgos exportados a: hallazgos_forenses.json")
        if args.pdf:
            print(f"[+] Reporte PDF generado: reporte_forense.pdf")
    else:
        print("[-] No se encontraron hallazgos")


if __name__ == "__main__":
    main()
