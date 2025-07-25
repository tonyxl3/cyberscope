import re
import requests
from bs4 import BeautifulSoup

from .utils import FINDINGS, logger
from .forensics import extraer_iocs


def analizar_pagina_web(url: str, timeout: int = 10) -> bool:
    """
    Realiza un análisis de seguridad básico en una página web:
    - Cabeceras
    - Contenido
    - IoCs
    - Posibles secretos
    """
    FINDINGS.append(f"[WEBSCAN] Iniciando escaneo de: {url}")
    try:
        response = requests.get(url, timeout=timeout)
    except requests.exceptions.RequestException as e:
        FINDINGS.append(f"[WEBSCAN_ERROR] No se pudo acceder a {url}: {e}")
        logger.error(f"Fallo al conectar con {url}: {e}")
        return False

    FINDINGS.append(f"[WEBSCAN] Código de estado: {response.status_code}")

    # === Cabeceras esperadas
    headers_esperadas = [
        "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
        "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"
    ]

    for header in headers_esperadas:
        if header not in response.headers:
            FINDINGS.append(f"[WEBHEADER_MISSING] {header} no está presente")
        else:
            FINDINGS.append(f"[WEBHEADER] {header}: {response.headers[header]}")

    # === Contenido visible y IoCs
    try:
        soup = BeautifulSoup(response.text, "html.parser")
        contenido = soup.get_text()
        FINDINGS.append(f"[WEBCONTENT] Longitud del contenido visible: {len(contenido)} caracteres")
        extraer_iocs(contenido)
    except Exception as e:
        FINDINGS.append(f"[WEBPARSE_ERROR] Error procesando contenido HTML: {e}")
        logger.warning(f"Error parsing HTML de {url}: {e}")

    # === Detección de posibles secretos
    patrones_secrets = [
        r"(api_key|apikey|secret|token|authorization)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}",
        r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"  # JWT
    ]

    for pattern in patrones_secrets:
        matches = re.findall(pattern, response.text, re.IGNORECASE)
        for match in matches:
            FINDINGS.append(f"[WEB_SECRET] Posible clave o token encontrado: {match[:80]}...")

    FINDINGS.append(f"[WEBSCAN] Análisis completo de: {url}")
    return True


def dirscan(url: str, wordlist_path: str, codes=[200, 301, 302]) -> None:
    """
    Prueba rutas comunes en una URL usando una wordlist local.
    """
    try:
        with open(wordlist_path) as f:
            paths = [line.strip() for line in f if line.strip()]
    except Exception as e:
        FINDINGS.append(f"[ERROR] No se pudo cargar wordlist: {e}")
        return

    FINDINGS.append(f"[DIRSCAN] Iniciando fuzzing en {url}")
    for path in paths:
        test_url = f"{url.rstrip('/')}/{path}"
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code in codes:
                FINDINGS.append(f"[DIR_FOUND] {test_url} - Código: {r.status_code}")
        except:
            continue
    FINDINGS.append("[DIRSCAN] Fuzzing completado")


def login_check(url: str) -> None:
    """
    Detecta formularios de login visibles en una página HTML.
    """
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        found = False

        if soup.find('form'):
            for form in soup.find_all('form'):
                inputs = [i.get('type') for i in form.find_all('input')]
                if 'password' in inputs:
                    FINDINGS.append(f"[LOGIN_FORM] Posible formulario de login en {url}")
                    found = True

        for keyword in ['admin', 'login', 'auth']:
            if keyword in url.lower():
                FINDINGS.append(f"[LOGIN_URL_HINT] URL sospechosa de login: {url}")
                found = True

        if not found:
            FINDINGS.append(f"[LOGINCHECK] No se detectó formulario de login en {url}")

    except Exception as e:
        FINDINGS.append(f"[ERROR] LoginCheck falló: {e}")
        logger.error(f"LoginCheck falló: {e}")
