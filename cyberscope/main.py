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


def main():
    parser = argparse.ArgumentParser(
        description="CyberScope v2.0 - Herramienta de Análisis Forense y Web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
    python main.py --hash archivo.txt
    python main.py --hash /ruta/directorio
    python main.py --buscar /ruta/directorio --pdf
    python main.py --exif imagen.jpg --json
    python main.py --ioc log.txt --pdf --json
    python main.py --webscan https://miweb.com --pdf
    python main.py --dirscan https://miweb.com wordlist.txt
    python main.py --whois openai.com --ipinfo 8.8.8.8
    python main.py --portscan 192.168.1.1
    python main.py --vulnscan https://ejemplo.com
    python main.py --sslcheck ejemplo.com
    python main.py --paramfuzz https://ejemplo.com/search
    python main.py --pentest https://ejemplo.com
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

