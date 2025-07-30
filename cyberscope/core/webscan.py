import re
import requests
import os
from bs4 import BeautifulSoup

from .utils import FINDINGS, logger
from .forensics import extraer_iocs

# === GROQ INTEGRATION ===
try:
    from groq import Groq
    GROQ_DISPONIBLE = True
except ImportError:
    GROQ_DISPONIBLE = False
    logger.warning("Groq no está instalado. Instalar con: pip install groq")

def test_groq_connection():
    """
    Prueba la conexión con Groq API y verifica que funcione correctamente.
    Retorna tuple (success: bool, message: str, model_info: dict)
    """
    if not GROQ_DISPONIBLE:
        return False, "Groq library no está instalada", {}
    
    api_key = os.getenv('GROQ_API_KEY')
    if not api_key:
        return False, "GROQ_API_KEY no está configurada", {}
    
    if not api_key.startswith('gsk_'):
        return False, "GROQ_API_KEY no tiene formato válido (debe empezar con 'gsk_')", {}
    
    try:
        # Inicializar cliente Groq
        client = Groq(api_key=api_key)
        
        # Test básico con una consulta simple
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": "Responde solo con 'OK' para confirmar que funciona"
                }
            ],
            model="llama-3.1-70b-versatile",
            max_tokens=10,
            temperature=0
        )
        
        response_content = chat_completion.choices[0].message.content.strip()
        
        # Información del modelo y uso
        model_info = {
            "model": chat_completion.model,
            "usage": {
                "prompt_tokens": chat_completion.usage.prompt_tokens,
                "completion_tokens": chat_completion.usage.completion_tokens,
                "total_tokens": chat_completion.usage.total_tokens
            },
            "response": response_content
        }
        
        if "OK" in response_content.upper():
            return True, "✅ Groq API funcionando correctamente", model_info
        else:
            return False, f"Respuesta inesperada: {response_content}", model_info
            
    except Exception as e:
        error_msg = str(e)
        if "authentication" in error_msg.lower():
            return False, "❌ Error de autenticación - Verifica tu API key", {}
        elif "rate_limit" in error_msg.lower():
            return False, "⚠️ Límite de velocidad alcanzado - Reintenta en unos segundos", {}
        elif "connection" in error_msg.lower():
            return False, "❌ Error de conexión - Verifica tu internet", {}
        else:
            return False, f"❌ Error: {error_msg}", {}

def analizar_con_groq(findings_text: str) -> str:
    """
    Envía los hallazgos técnicos a Groq para obtener un análisis profesional
    en lenguaje simple y recomendaciones específicas.
    """
    if not GROQ_DISPONIBLE:
        return "⚠️ Análisis IA no disponible - Groq no instalado"
    
    api_key = os.getenv('GROQ_API_KEY')
    if not api_key:
        return "⚠️ Análisis IA no disponible - API key no configurada"
    
    try:
        client = Groq(api_key=api_key)
        
        prompt = f"""
Eres un experto en ciberseguridad. Analiza los siguientes hallazgos técnicos y proporciona:

1. RESUMEN EJECUTIVO (2-3 líneas en español)
2. NIVEL DE RIESGO: [Crítico/Alto/Medio/Bajo]
3. VULNERABILIDADES IDENTIFICADAS (explica en términos simples)
4. RECOMENDACIONES ESPECÍFICAS (paso a paso)

HALLAZGOS TÉCNICOS:
{findings_text}

Responde en español, de forma clara y profesional. Si no hay vulnerabilidades críticas, menciona buenas prácticas de seguridad encontradas.
"""
        
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "Eres un consultor senior en ciberseguridad especializado en análisis de vulnerabilidades web y explicaciones técnicas para audiencias no técnicas."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ],
            model="llama-3.1-70b-versatile",
            max_tokens=1500,
            temperature=0.3
        )
        
        return chat_completion.choices[0].message.content
        
    except Exception as e:
        logger.error(f"Error en análisis Groq: {e}")
        return f"⚠️ Error en análisis IA: {str(e)}"

def inicializar_groq():
    """
    Inicializa y verifica la conexión con Groq al arrancar la aplicación.
    Debe llamarse en el startup de tu aplicación Flask.
    """
    success, message, model_info = test_groq_connection()
    
    if success:
        logger.info(f"✅ Groq API configurada - Análisis IA disponible")
        logger.info(f"   Modelo: {model_info.get('model', 'N/A')}")
        logger.info(f"   Uso test: {model_info.get('usage', {}).get('total_tokens', 0)} tokens")
        FINDINGS.append("[GROQ_INIT] ✅ Análisis IA con Groq disponible")
    else:
        logger.warning(f"⚠️ Groq API no disponible: {message}")
        FINDINGS.append(f"[GROQ_INIT] ⚠️ Análisis IA no disponible: {message}")
        FINDINGS.append("[GROQ_INIT] Funcionando en modo fallback (solo análisis técnico)")
    
    return success

# === TU CÓDIGO ORIGINAL ===
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
