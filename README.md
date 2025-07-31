# IRC9.1-Mu-oz-Sanchez-Jose-Antonio

## CyberScope v2.0 - Herramienta de Análisis Forense Digital y Pentesting

### 🌐 Interfaz Web con Docker

CyberScope ahora incluye una interfaz web moderna desarrollada con Flask que permite:

- **Análisis Web Masivo**: Pega múltiples URLs y analízalas automáticamente
- **Análisis Forense de Archivos**: Sube archivos para análisis forense
- **Reportes Descargables**: Genera reportes en PDF y JSON
- **Interfaz Intuitiva**: Moderna y fácil de usar con progreso en tiempo real
- **Herramientas de Pentesting**: Escaneo de puertos, detección de vulnerabilidades, análisis SSL
- **🤖 Análisis Inteligente con IA**: Integración con ChatGPT para explicaciones comprensibles
- **📄 Reportes PDF Mejorados**: Generación automática de reportes profesionales

#### 🚀 Ejecutar con Docker

```bash
# Construir y ejecutar con Docker Compose
docker-compose up --build

# Acceder a la interfaz web
# http://localhost:5000
```

#### 🔧 Configuración de ChatGPT (Opcional)

Para habilitar el análisis inteligente con Groq (GRATUITO), configura tu API key:

```bash
# Opción 1: Archivo .env (Recomendado)
echo "GROQ_API_KEY=gsk_tu_api_key_aqui" > .env
docker-compose up --build

# Opción 2: Variable de entorno
export GROQ_API_KEY="gsk_tu_api_key_aqui"
docker-compose up --build
```

#### 🆓 Obtener API Key de Groq (Gratis)

1. **Ve a**: https://console.groq.com
2. **Regístrate** con tu email (completamente gratis)
3. **Crea API Key**: Ve a "API Keys" → "Create API Key"
4. **Copia la key** (empieza con `gsk_`)
5. **Configura**: Agrega a `.env` o variable de entorno

**Sin API Key**: CyberScope funcionará con un analizador de respaldo que proporciona análisis básico usando reglas predefinidas.

#### 📋 Características de la Interfaz Web

**Análisis Web:**
- ✅ Análisis web básico (headers, contenido, IoCs)
- ✅ Detección de vulnerabilidades (SQL Injection, XSS, etc.)
- ✅ Análisis de certificados SSL
- ✅ Fuzzing de parámetros web
- ✅ Información WHOIS
- ✅ Escaneo de puertos
- ✅ Progreso en tiempo real con cancelación de análisis
- ✅ **🤖 Análisis inteligente**: Explicaciones comprensibles de hallazgos técnicos
- ✅ **📊 Nivel de riesgo**: Evaluación automática del riesgo de seguridad

**Análisis Forense:**
- ✅ Hash de archivos (MD5, SHA1, SHA256)
- ✅ Extracción de metadatos EXIF
- ✅ Metadatos de archivos PDF
- ✅ Extracción de IoCs de archivos de texto
- ✅ **🤖 Análisis forense inteligente**: Interpretación automática de hallazgos

**Reportes:**
- ✅ Generación automática de reportes PDF y JSON
- ✅ Descarga directa desde la interfaz web
- ✅ Historial de reportes generados
- ✅ **📄 Reportes PDF profesionales**: Con análisis técnico y explicaciones simplificadas
- ✅ **🎯 Resumen ejecutivo**: Análisis comprensible para usuarios no técnicos
- ✅ **⚠️ Evaluación de riesgos**: Clasificación automática de vulnerabilidades
- ✅ **💡 Recomendaciones**: Sugerencias específicas de seguridad

### Instalación

1. Clona el repositorio:
```bash
git clone <url-del-repositorio>
cd IRC9.1-Mu-oz-Sanchez-Jose-Antonio
```

2. Para uso local, crea un entorno virtual (recomendado):
```bash
python3 -m venv cyberscope-env
source cyberscope-env/bin/activate  # En Linux/Mac
# o
cyberscope-env\Scripts\activate     # En Windows
```

3. Instala las dependencias:
```bash
pip install -r requirements.txt
```

### Uso

#### Línea de comandos:
```bash
cd cyberscope
python main.py --help
```

#### Interfaz Web:
```bash
docker-compose up --build
# Abrir http://localhost:5000 en el navegador
```

### Ejemplos de uso:

```bash
# Hashear un archivo
python cyberscope/main.py --hash archivo.txt

# Buscar archivos sospechosos
python cyberscope/main.py --buscar /ruta/directorio --pdf

# Extraer metadatos EXIF
python cyberscope/main.py --exif imagen.jpg --json

# Análisis web
python cyberscope/main.py --webscan https://ejemplo.com --pdf

# Pentesting
python cyberscope/main.py --portscan 192.168.1.1 --pdf
python cyberscope/main.py --vulnscan https://ejemplo.com --json
python cyberscope/main.py --sslcheck ejemplo.com
python cyberscope/main.py --paramfuzz https://ejemplo.com/search
python cyberscope/main.py --pentest https://ejemplo.com --pdf --json

# Extraer IoCs de un archivo
python cyberscope/main.py --ioc log.txt --json --pdf
```

### Características:

- ✅ Análisis forense de archivos (hashing MD5, SHA1, SHA256)
- ✅ Extracción de metadatos EXIF de imágenes
- ✅ Análisis de metadatos PDF
- ✅ Búsqueda de archivos sospechosos
- ✅ Extracción de IoCs (IPs, URLs, emails, hashes)
- ✅ Análisis de seguridad web
- ✅ Consultas WHOIS e información de IPs
- ✅ Generación de reportes en PDF y JSON
- ✅ Escaneo de puertos TCP
- ✅ Detección de vulnerabilidades web básicas
- ✅ Análisis de certificados SSL
- ✅ Fuzzing de parámetros web
- ✅ Escaneo completo de pentesting
- ✅ **🤖 Análisis inteligente con IA**: Interpretación automática de hallazgos
- ✅ **📊 Evaluación de riesgos**: Clasificación automática de vulnerabilidades
- ✅ **💡 Recomendaciones inteligentes**: Sugerencias específicas de seguridad

### Interfaz Web:

- ✅ Interfaz web moderna con Flask
- ✅ Análisis masivo de URLs
- ✅ Subida de archivos para análisis forense
- ✅ Reportes descargables (PDF/JSON)
- ✅ Progreso en tiempo real
- ✅ Cancelación de análisis
- ✅ Dockerizado para fácil despliegue
- ✅ **🤖 Integración con ChatGPT**: Análisis inteligente opcional
- ✅ **📄 Reportes PDF profesionales**: Con análisis técnico y simplificado
- ✅ **🎯 Dashboard intuitivo**: Interfaz comprensible para usuarios no técnicos
- ✅ **🔗 Análisis Remoto SSH**: Análisis forense sin dejar rastros en servidores

### Dependencias:

- `requests`: Para análisis web
- `beautifulsoup4`: Para parsing HTML
- `Pillow`: Para metadatos EXIF
- `PyPDF2`: Para metadatos PDF
- `reportlab`: Para generación de reportes PDF
- `ipwhois`: Para consultas de información IP
- `lxml`: Parser XML/HTML adicional
- `Flask`: Framework web para la interfaz
- `Werkzeug`: Utilidades web para Flask
- `PyYAML`: Para archivos de configuración YAML

### 🤖 Análisis Inteligente:

CyberScope integra capacidades de IA para hacer los resultados más comprensibles:

- **Análisis automático**: Los hallazgos técnicos se envían automáticamente para análisis
- **Explicaciones simplificadas**: Convierte jerga técnica en lenguaje comprensible
- **Evaluación de riesgos**: Clasifica automáticamente el nivel de riesgo (Alto/Medio/Bajo)
- **Recomendaciones específicas**: Proporciona acciones concretas a tomar
- **Glosario técnico**: Explica términos especializados encontrados
- **Análisis de respaldo**: Funciona sin API key usando reglas predefinidas

### Arquitectura:
- **Versión modular**: Código organizado en módulos especializados
- **Interfaz web**: Flask con templates Bootstrap para una experiencia moderna
- **Dockerizado**: Fácil despliegue con Docker y docker-compose
- **IA integrada**: Análisis inteligente opcional con ChatGPT
- **Reportes profesionales**: Generación automática de documentos PDF completos
- **Análisis remoto SSH**: Capacidades forenses remotas sin rastros

### 🔗 **Análisis Remoto SSH:**

CyberScope incluye capacidades avanzadas de análisis forense remoto:

- **Sin rastros**: No deja archivos en el servidor objetivo
- **Análisis integral**: Sistema, usuarios, red, procesos, logs
- **Evaluación de vulnerabilidades**: SSH, web, bases de datos, escalación de privilegios
- **Evidencia forense**: Cadena de custodia y hashes de integridad
- **Múltiples tipos de escaneo**: Rápido, vulnerabilidades, completo
- **Configuración flexible**: Archivos YAML para personalización

#### **Características del análisis remoto:**
- ✅ **Conexión SSH segura** con soporte para claves privadas
- ✅ **Análisis sin rastros** - no crea archivos en el servidor objetivo
- ✅ **Evidencia forense** con cadena de custodia
- ✅ **Detección de vulnerabilidades** específicas por categoría
- ✅ **Análisis de logs** sin descargar archivos completos
- ✅ **Evaluación de configuraciones** de seguridad
- ✅ **Integración con IA** para análisis comprensible