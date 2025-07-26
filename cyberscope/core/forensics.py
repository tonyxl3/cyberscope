import os
import hashlib
import re
from typing import Dict, List, Optional
from datetime import datetime

from .utils import FINDINGS, logger

# PIL (EXIF)
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("PIL no disponible. Funciones EXIF deshabilitadas.")

# PDF
try:
    from PyPDF2 import PdfReader
    PYPDF2_AVAILABLE = True
except ImportError:
    PYPDF2_AVAILABLE = False
    logger.warning("PyPDF2 no disponible. Funciones PDF deshabilitadas.")


def hash_file(filepath: str, algos: List[str] = ["md5", "sha1", "sha256"]) -> Optional[Dict[str, str]]:
    try:
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise FileNotFoundError(f"{filepath} no válido")

        hashes = {}
        file_size = os.path.getsize(filepath)

        for algo in algos:
            try:
                h = hashlib.new(algo)
                with open(filepath, 'rb') as f:
                    while chunk := f.read(8192):
                        h.update(chunk)
                hashes[algo] = h.hexdigest()
                FINDINGS.append(f"[HASH] {algo.upper()} - {filepath}: {hashes[algo]}")
            except ValueError as e:
                logger.error(f"Hash inválido '{algo}': {e}")
                continue

        FINDINGS.append(f"[FILE_SIZE] {filepath}: {file_size} bytes")
        return hashes

    except Exception as e:
        logger.error(f"Error hashing {filepath}: {e}")
        FINDINGS.append(f"[ERROR] {e}")
        return None


def hash_directory(dirpath: str, algos: List[str] = ["md5", "sha1", "sha256"]) -> Optional[Dict[str, Dict[str, str]]]:
    try:
        if not os.path.exists(dirpath) or not os.path.isdir(dirpath):
            raise FileNotFoundError(f"{dirpath} no válido")

        hashes = {}
        count = 0

        for root, _, files in os.walk(dirpath):
            for file in files:
                full_path = os.path.join(root, file)
                h = hash_file(full_path, algos)
                if h:
                    hashes[full_path] = h
                    count += 1

        FINDINGS.append(f"[DIRECTORY_SCAN] {count} archivos procesados en {dirpath}")
        return hashes

    except Exception as e:
        logger.error(f"Error procesando directorio {dirpath}: {e}")
        FINDINGS.append(f"[ERROR] {e}")
        return None


def get_file_timestamps(filepath: str) -> Optional[Dict[str, str]]:
    try:
        stats = os.stat(filepath)
        times = {
            "creacion": datetime.fromtimestamp(stats.st_ctime).isoformat(),
            "modificacion": datetime.fromtimestamp(stats.st_mtime).isoformat(),
            "acceso": datetime.fromtimestamp(stats.st_atime).isoformat()
        }

        for k, v in times.items():
            FINDINGS.append(f"[TIMESTAMP] {k} - {filepath}: {v}")
        return times

    except Exception as e:
        logger.error(f"Error extrayendo timestamps de {filepath}: {e}")
        FINDINGS.append(f"[ERROR] {e}")
        return None


def buscar_sospechosos(path: str, extensiones: List[str] = [".exe", ".bat", ".dll", ".scr", ".ps1", ".vbs", ".cmd", ".com"]) -> List[str]:
    encontrados = []
    try:
        for root, _, files in os.walk(path):
            for f in files:
                if any(f.lower().endswith(ext) for ext in extensiones):
                    full_path = os.path.join(root, f)
                    encontrados.append(full_path)
                    FINDINGS.append(f"[SOSPECHOSO] {full_path}")
                    get_file_timestamps(full_path)

        FINDINGS.append(f"[SCAN_RESULT] {len(encontrados)} archivos sospechosos encontrados en {path}")
        return encontrados

    except Exception as e:
        logger.error(f"Error buscando sospechosos en {path}: {e}")
        FINDINGS.append(f"[ERROR] {e}")
        return []


def extraer_exif(img_path: str) -> Optional[Dict]:
    if not PIL_AVAILABLE:
        FINDINGS.append(f"[ERROR] PIL no disponible para {img_path}")
        return None

    try:
        with Image.open(img_path) as img:
            exif_data = img._getexif()
            if not exif_data:
                FINDINGS.append(f"[EXIF] {img_path}: Sin metadatos")
                return None

            exif_dict = {}
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                exif_dict[tag] = value
                FINDINGS.append(f"[EXIF] {img_path} - {tag}: {value}")
            return exif_dict

    except Exception as e:
        logger.error(f"EXIF error en {img_path}: {e}")
        FINDINGS.append(f"[ERROR] {e}")
        return None


def extraer_pdf_meta(pdf_path: str) -> Optional[Dict]:
    if not PYPDF2_AVAILABLE:
        FINDINGS.append(f"[ERROR] PyPDF2 no disponible para {pdf_path}")
        return None

    try:
        with open(pdf_path, 'rb') as f:
            reader = PdfReader(f)
            meta = reader.metadata
            info = {}

            if not meta:
                FINDINGS.append(f"[PDF_META] {pdf_path}: Sin metadatos")
                return None

            for k, v in meta.items():
                info[k] = str(v)
                FINDINGS.append(f"[PDF_META] {pdf_path} - {k}: {v}")

            FINDINGS.append(f"[PDF_INFO] {pdf_path} - Páginas: {len(reader.pages)}")
            FINDINGS.append(f"[PDF_INFO] {pdf_path} - Encriptado: {reader.is_encrypted}")
            return info

    except Exception as e:
        logger.error(f"PDF meta error en {pdf_path}: {e}")
        FINDINGS.append(f"[ERROR] {e}")
        return None


def extraer_iocs(texto: str) -> Optional[Dict[str, List[str]]]:
    try:
        patterns = {
            "ips": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            "urls": r'https?://[^\s<>"{}|\\^`\[\]]+',
            "emails": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "domains": r'\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b',
            "md5": r'\b[a-fA-F0-9]{32}\b',
            "sha1": r'\b[a-fA-F0-9]{40}\b',
            "sha256": r'\b[a-fA-F0-9]{64}\b'
        }

        results = {}

        for ioc_type, pattern in patterns.items():
            matches = list(set(re.findall(pattern, texto)))
            results[ioc_type] = matches
            for match in matches:
                FINDINGS.append(f"[IOC] {ioc_type.upper()}: {match}")

        total = sum(len(v) for v in results.values())
        FINDINGS.append(f"[IOC_SUMMARY] Total de IoCs encontrados: {total}")
        return results

    except Exception as e:
        logger.error(f"Error extrayendo IoCs: {e}")
        FINDINGS.append(f"[ERROR] {e}")
        return None
