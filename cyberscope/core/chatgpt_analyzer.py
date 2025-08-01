import time
import json
import requests
from datetime import datetime
import re
from .utils import FINDINGS, logger

# Verificar disponibilidad de Groq
try:
    from groq import Groq
    GROQ_AVAILABLE = True
    logger.info("✅ Librería Groq importada correctamente")
except ImportError:
    GROQ_AVAILABLE = False
    logger.warning("⚠️ Librería Groq no disponible. Instalar con: pip install groq")
    Groq = None

class GroqAnalyzer:
    def __init__(self, api_key=None):
        """
        Inicializa el analizador de Groq (reemplazo gratuito de ChatGPT)
        
        Args:
            api_key (str): API key de Groq (gratuita)
        """
        self.api_key = api_key
        self.model = "llama-3.1-70b-versatile"
        self.available = GROQ_AVAILABLE and bool(api_key)
        
        if not GROQ_AVAILABLE:
            logger.warning("⚠️ Groq no disponible - librería no instalada")
        elif not api_key:
            logger.warning("⚠️ Groq no disponible - API key no configurada")
        elif not api_key.startswith('gsk_'):
            logger.warning("⚠️ Groq API key parece inválida (debe empezar con 'gsk_')")
            self.available = False
        else:
            logger.info("✅ Groq configurado correctamente")
        
    def analyze_findings_with_groq(self, findings_list, target_info=None):
        """
        Envía los hallazgos a Groq para análisis y explicación
        
        Args:
            findings_list (list): Lista de hallazgos técnicos
            target_info (dict): Información del objetivo analizado
            
        Returns:
            dict: Análisis procesado por Groq
        """
        if not self.available:
            logger.warning("Groq no disponible, saltando análisis IA")
            return None
            
        try:
            # Preparar el prompt para Groq
            prompt = self._create_analysis_prompt(findings_list, target_info)
            
            # Enviar a Groq API
            response = self._send_to_groq_api(prompt)
            
            if response and isinstance(response, str) and len(response.strip()) > 100:
                processed_analysis = self._process_groq_response(response)
                
                if processed_analysis and processed_analysis.get("executive_summary"):
                    FINDINGS.append(f"[GROQ_ANALYSIS] Análisis completado - {len(processed_analysis.get('key_findings', []))} puntos clave identificados")
                    return processed_analysis
                else:
                    logger.warning(f"⚠️ Respuesta de Groq procesada pero incompleta")
                    FINDINGS.append("[GROQ_WARNING] Respuesta de Groq incompleta, usando fallback")
            else:
                logger.warning(f"⚠️ Respuesta de Groq muy corta o vacía: {len(response.strip()) if response else 0} caracteres")
                if response:
                    logger.debug(f"Respuesta Groq: {response[:200]}...")
                    
            FINDINGS.append("[GROQ_ERROR] No se pudo obtener análisis de Groq")
            return None

  
        except Exception as e:
            logger.error(f"Error en análisis Groq: {e}")
            FINDINGS.append(f"[GROQ_ERROR] Error en análisis: {str(e)}")
            return None
    
    def _create_analysis_prompt(self, findings_list, target_info=None):
        """Crea el prompt optimizado para Groq"""
        
        # Información del objetivo
        target_section = ""
        if target_info:
            target_section = f"""
INFORMACIÓN DEL OBJETIVO:
- URL/Host: {target_info.get('url', 'N/A')}
- Tipo de análisis: {', '.join(target_info.get('analysis_types', []))}
- Fecha: {target_info.get('timestamp', datetime.now().isoformat())}
"""
        
        # Hallazgos técnicos (limitar para no exceder tokens)
        findings_text = "\n".join([f"- {finding}" for finding in findings_list[:30]])  # Reducir para evitar límites
        
        # Si hay muchos hallazgos, agregar resumen
        if len(findings_list) > 30:
            findings_text += f"\n... y {len(findings_list) - 30} hallazgos adicionales"
        
        prompt = f"""
Eres un experto en ciberseguridad y análisis forense digital. Analiza los siguientes hallazgos técnicos y proporciona una explicación clara y comprensible para usuarios no técnicos.

{target_section}

HALLAZGOS TÉCNICOS ENCONTRADOS:
{findings_text}

Por favor, proporciona un análisis estructurado que incluya:

1. RESUMEN EJECUTIVO (2-3 líneas): Explicación simple de qué se encontró y su importancia

2. NIVEL DE RIESGO: Evalúa como Alto/Medio/Bajo con justificación clara

3. HALLAZGOS PRINCIPALES: Los 5 hallazgos más críticos explicados en lenguaje simple:
   - ¿Qué significa cada hallazgo?
   - ¿Por qué es importante?
   - ¿Qué riesgo representa?

4. VULNERABILIDADES IDENTIFICADAS: Problemas de seguridad específicos encontrados:
   - Descripción del problema
   - Impacto potencial
   - Urgencia de corrección

5. RECOMENDACIONES ESPECÍFICAS: Acciones concretas y priorizadas:
   - Qué hacer primero (urgente)
   - Qué hacer después (importante)
   - Medidas preventivas

6. GLOSARIO TÉCNICO: Explicación de términos técnicos mencionados

IMPORTANTE: 
- Usa un lenguaje claro y accesible
- Evita jerga técnica innecesaria
- Si usas términos técnicos, explícalos inmediatamente
- Se específico en las recomendaciones
- Prioriza por nivel de riesgo
"""
        
        return prompt
    
    def _send_to_groq_api(self, prompt):
        """
        Envía el prompt a la API de Groq
        
        Args:
            prompt (str): Prompt a enviar
            
        Returns:
            str: Respuesta de Groq o None si hay error
        """
        if not self.available:
            logger.warning("No se proporcionó API key de Groq")
            return None
        
        try:
            # Usar la librería oficial de Groq
            client = Groq(api_key=self.api_key)
            
            logger.info(f"🤖 Enviando análisis a Groq AI... ({len(prompt)} caracteres)")
            
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "Eres un experto en ciberseguridad que explica hallazgos técnicos de forma clara y comprensible. Proporciona análisis estructurados, precisos y orientados a la acción. Usa formato claro con saltos de línea apropiados."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                model=self.model,
                max_tokens=3000,  # Aumentar límite
                temperature=0.2,  # Más determinístico
                top_p=0.8
            )
            
            content = chat_completion.choices[0].message.content
            logger.info(f"✅ Análisis Groq completado: {len(content)} caracteres")
            return self._sanitize_response_text(content)
                
        except Exception as e:
            error_msg = str(e).lower()
            if "authentication" in error_msg or "unauthorized" in error_msg:
                logger.error("❌ API key de Groq inválida o expirada")
                FINDINGS.append("[GROQ_ERROR] API key inválida - Verifica tu configuración")
            elif "rate_limit" in error_msg or "429" in error_msg:
                logger.warning("⚠️ Límite de rate de Groq alcanzado, reintentando...")
                time.sleep(10)
                try:
                    logger.info("🔄 Reintentando llamada a Groq...")
                    client = Groq(api_key=self.api_key)
                    chat_completion = client.chat.completions.create(
                        messages=[
                            {
                                "role": "system",
                                "content": "Eres un experto en ciberseguridad. Proporciona análisis claros y estructurados."
                            },
                            {
                                "role": "user",
                                "content": prompt[:4000]  # Reducir tamaño en retry
                            }
                        ],
                        model=self.model,
                        max_tokens=2000,
                        temperature=0.3
                    )
                    content = chat_completion.choices[0].message.content
                    logger.info("✅ Retry exitoso")
                    return self._sanitize_response_text(content)
                except:
                    logger.error("❌ Retry falló también")
                    return None
            elif "context_length" in error_msg or "too long" in error_msg:
                logger.warning("⚠️ Prompt muy largo, reduciendo tamaño...")
                try:
                    # Retry con prompt más corto
                    short_prompt = prompt[:3000] + "\n\nPor favor, proporciona un análisis conciso de los hallazgos más importantes."
                    return self._send_to_groq_api(short_prompt)
                except:
                    logger.error("❌ Retry con prompt corto falló")
                    return None
            else:
                logger.error(f"❌ Error enviando a Groq API: {e}")
            return None
    
    def _process_groq_response(self, response_text):
        """
        Procesa la respuesta de Groq para estructurarla
        
        Args:
            response_text (str): Respuesta cruda de Groq
            
        Returns:
            dict: Respuesta estructurada
        """
        processed = {
            "timestamp": datetime.now().isoformat(),
            "original_text": response_text,
            "executive_summary": "",
            "risk_level": "Medio",
            "key_findings": [],
            "vulnerabilities": [],
            "recommendations": [],
            "technical_terms": [],
            "simplified_text": response_text,
            "analyzer": "Groq Llama-3.1-70B"
        }
        
        try:
            # Patrones mejorados para extraer secciones
            sections = {
                "executive_summary": r"(?:RESUMEN EJECUTIVO|1\.)[:\s]*(.+?)(?=\n(?:\d+\.|NIVEL DE RIESGO|HALLAZGOS|$))",
                "risk_level": r"(?:NIVEL DE RIESGO|2\.)[:\s]*(.+?)(?=\n(?:\d+\.|HALLAZGOS|$))",
                "key_findings": r"(?:HALLAZGOS PRINCIPALES|3\.)[:\s]*(.+?)(?=\n(?:\d+\.|VULNERABILIDADES|$))",
                "vulnerabilities": r"(?:VULNERABILIDADES IDENTIFICADAS|4\.)[:\s]*(.+?)(?=\n(?:\d+\.|RECOMENDACIONES|$))",
                "recommendations": r"(?:RECOMENDACIONES|5\.)[:\s]*(.+?)(?=\n(?:\d+\.|GLOSARIO|TÉRMINOS|$))",
                "technical_terms": r"(?:GLOSARIO|TÉRMINOS|6\.)[:\s]*(.+?)$"
            }
            
            for section, pattern in sections.items():
                match = re.search(pattern, response_text, re.DOTALL | re.IGNORECASE)
                if match:
                    content = match.group(1).strip()
                    
                    if section in ["key_findings", "vulnerabilities", "recommendations", "technical_terms"]:
                        # Convertir a lista, manejando diferentes formatos
                        items = []
                        
                        # Dividir por líneas y procesar
                        lines = content.split('\n')
                        current_item = ""
                        
                        for line in lines:
                            line = line.strip()
                            if not line:
                                continue
                                
                            # Detectar nuevos elementos (-, •, números, etc.)
                            if re.match(r'^[-•*\d+\.]\s*', line) or (current_item and not line.startswith(' ')):
                                if current_item:
                                    items.append(current_item.strip())
                                current_item = re.sub(r'^[-•*\d+\.]\s*', '', line)
                            else:
                                current_item += " " + line
                        
                        if current_item:
                            items.append(current_item.strip())
                        
                        processed[section] = [item for item in items if len(item) > 10]  # Filtrar items muy cortos
                    else:
                        processed[section] = content
            
            # Extraer nivel de riesgo específico
            risk_text = processed.get("risk_level", "").lower()
            if "alto" in risk_text or "high" in risk_text or "crítico" in risk_text:
                processed["risk_level"] = "Alto"
            elif "bajo" in risk_text or "low" in risk_text or "mínimo" in risk_text:
                processed["risk_level"] = "Bajo"
            else:
                processed["risk_level"] = "Medio"
            
            # Validar que tenemos contenido útil
            if not processed["executive_summary"] and len(response_text) > 100:
                # Fallback: usar los primeros párrafos como resumen
                paragraphs = response_text.split('\n\n')
                processed["executive_summary"] = paragraphs[0] if paragraphs else "Análisis completado"
            
        except Exception as e:
            logger.error(f"Error procesando respuesta Groq: {e}")
            # Fallback básico
            processed["executive_summary"] = "Análisis técnico completado con Groq AI"
            processed["simplified_text"] = response_text[:1000] + "..." if len(response_text) > 1000 else response_text
        
        return processed

class GroqFallbackAnalyzer:
    """
    Analizador de respaldo mejorado que funciona sin API
    Proporciona análisis más inteligente usando reglas predefinidas
    """
    
    def __init__(self):
        self.risk_keywords = {
            "alto": [
                "sql injection", "xss", "command injection", "directory traversal", 
                "rce", "authentication bypass", "privilege escalation", "buffer overflow",
                "code execution", "remote code", "arbitrary file", "path traversal"
            ],
            "medio": [
                "information disclosure", "weak ssl", "missing headers", "outdated", 
                "vulnerable", "weak cipher", "expired certificate", "misconfiguration",
                "sensitive data", "unencrypted", "weak authentication"
            ],
            "bajo": [
                "banner", "version", "port open", "whois", "dns", "fingerprint",
                "service detection", "header missing", "cookie", "redirect"
            ]
        }
        
        self.vulnerability_patterns = {
            "SQL Injection": ["sql", "injection", "sqli", "database"],
            "Cross-Site Scripting": ["xss", "script", "javascript", "reflected"],
            "Command Injection": ["command", "injection", "shell", "exec"],
            "Directory Traversal": ["directory", "traversal", "path", "../"],
            "SSL/TLS Issues": ["ssl", "tls", "certificate", "cipher", "protocol"],
            "Authentication Issues": ["auth", "login", "password", "session"],
            "Information Disclosure": ["information", "disclosure", "leak", "expose"],
            "Configuration Issues": ["config", "misconfiguration", "setting", "default"]
        }
    
    def analyze_findings_with_rules(self, findings_list, target_info=None):
        """
        Analiza hallazgos usando reglas inteligentes mejoradas
        
        Args:
            findings_list (list): Lista de hallazgos
            target_info (dict): Información del objetivo
            
        Returns:
            dict: Análisis estructurado
        """
        try:
            # Análisis mejorado
            analysis = {
                "timestamp": datetime.now().isoformat(),
                "executive_summary": self._generate_smart_summary(findings_list, target_info),
                "risk_level": self._calculate_risk_level(findings_list),
                "key_findings": self._extract_key_findings(findings_list),
                "vulnerabilities": self._extract_vulnerabilities_detailed(findings_list),
                "recommendations": self._generate_smart_recommendations(findings_list),
                "technical_terms": self._extract_technical_terms(findings_list),
                "simplified_text": self._create_comprehensive_report(findings_list, target_info),
                "analyzer": "CyberScope Smart Analyzer"
            }
            
            FINDINGS.append(f"[SMART_ANALYSIS] Análisis inteligente completado - Riesgo: {analysis['risk_level']}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error en análisis inteligente: {e}")
            return None
    
    def _generate_smart_summary(self, findings_list, target_info):
        """Genera un resumen ejecutivo inteligente"""
        total_findings = len(findings_list)
        findings_text = " ".join(findings_list).lower()
        
        # Contar vulnerabilidades por categoría
        vuln_counts = {}
        for vuln_type, keywords in self.vulnerability_patterns.items():
            count = sum(1 for keyword in keywords if keyword in findings_text)
            if count > 0:
                vuln_counts[vuln_type] = count
        
        high_risk_count = sum(1 for keyword in self.risk_keywords["alto"] if keyword in findings_text)
        medium_risk_count = sum(1 for keyword in self.risk_keywords["medio"] if keyword in findings_text)
        
        # Determinar el tipo de objetivo
        target_type = "sistema"
        if target_info:
            url = target_info.get('url', '').lower()
            if 'http' in url:
                target_type = "aplicación web"
            elif 'ssh' in url:
                target_type = "servidor remoto"
            elif 'archivo' in url:
                target_type = "archivo digital"
        
        # Generar resumen contextual
        if high_risk_count > 3:
            severity = "múltiples vulnerabilidades críticas"
            action = "requiere atención inmediata"
        elif high_risk_count > 0:
            severity = f"{high_risk_count} vulnerabilidad(es) crítica(s)"
            action = "requiere corrección urgente"
        elif medium_risk_count > 5:
            severity = "varios problemas de seguridad"
            action = "deben ser revisados"
        elif medium_risk_count > 0:
            severity = f"{medium_risk_count} problema(s) de seguridad"
            action = "deben ser evaluados"
        else:
            severity = "problemas menores de configuración"
            action = "pueden ser mejorados"
        
        # Mencionar vulnerabilidades específicas si las hay
        vuln_mention = ""
        if vuln_counts:
            top_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:2]
            vuln_names = [vuln[0] for vuln in top_vulns]
            vuln_mention = f", incluyendo {' y '.join(vuln_names).lower()}"
        
        return f"El análisis de {target_type} identificó {total_findings} hallazgos con {severity}{vuln_mention} que {action}."
    
    def _calculate_risk_level(self, findings_list):
        """Calcula el nivel de riesgo con lógica mejorada"""
        findings_text = " ".join(findings_list).lower()
        
        high_risk_score = sum(2 for keyword in self.risk_keywords["alto"] if keyword in findings_text)
        medium_risk_score = sum(1 for keyword in self.risk_keywords["medio"] if keyword in findings_text)
        
        total_score = high_risk_score + medium_risk_score
        
        if high_risk_score >= 3 or total_score >= 8:
            return "Alto"
        elif high_risk_score >= 1 or total_score >= 3:
            return "Medio"
        else:
            return "Bajo"
    
    def _extract_vulnerabilities_detailed(self, findings_list):
        """Extrae vulnerabilidades con descripciones detalladas"""
        vulnerabilities = []
        findings_text = " ".join(findings_list).lower()
        
        vuln_descriptions = {
            "SQL Injection": "Permite a atacantes insertar código SQL malicioso para acceder o modificar bases de datos sin autorización",
            "Cross-Site Scripting": "Permite ejecutar scripts maliciosos en navegadores de usuarios, comprometiendo su seguridad",
            "Command Injection": "Permite a atacantes ejecutar comandos del sistema operativo, comprometiendo completamente el servidor",
            "Directory Traversal": "Permite acceder a archivos y directorios fuera del directorio web autorizado",
            "SSL/TLS Issues": "Problemas en certificados o configuración que comprometen la seguridad de las comunicaciones",
            "Authentication Issues": "Debilidades en el sistema de autenticación que facilitan accesos no autorizados",
            "Information Disclosure": "Exposición de información sensible que puede ser utilizada por atacantes",
            "Configuration Issues": "Configuraciones inseguras que crean vulnerabilidades de seguridad"
        }
        
        for vuln_type, keywords in self.vulnerability_patterns.items():
            if any(keyword in findings_text for keyword in keywords):
                description = vuln_descriptions.get(vuln_type, "Problema de seguridad identificado")
                vulnerabilities.append(f"{vuln_type}: {description}")
        
        return vulnerabilities
    
    def _generate_smart_recommendations(self, findings_list):
        """Genera recomendaciones inteligentes basadas en hallazgos"""
        findings_text = " ".join(findings_list).lower()
        recommendations = []
        
        # Recomendaciones específicas por tipo de vulnerabilidad
        if any(keyword in findings_text for keyword in ["sql", "injection"]):
            recommendations.append("CRÍTICO: Implementar prepared statements y validación de entrada para prevenir inyección SQL")
        
        if any(keyword in findings_text for keyword in ["xss", "script"]):
            recommendations.append("IMPORTANTE: Implementar filtrado de salida y Content Security Policy (CSP)")
        
        if any(keyword in findings_text for keyword in ["ssl", "certificate", "expired"]):
            recommendations.append("URGENTE: Renovar certificados SSL y configurar protocolos TLS seguros")
        
        if any(keyword in findings_text for keyword in ["header", "missing"]):
            recommendations.append("Configurar cabeceras de seguridad (HSTS, X-Frame-Options, X-Content-Type-Options)")
        
        if any(keyword in findings_text for keyword in ["outdated", "version", "vulnerable"]):
            recommendations.append("Actualizar software y componentes a las versiones más recientes")
        
        if any(keyword in findings_text for keyword in ["auth", "login", "password"]):
            recommendations.append("Fortalecer mecanismos de autenticación e implementar autenticación de dos factores")
        
        # Recomendaciones generales
        recommendations.extend([
            "Realizar auditorías de seguridad periódicas",
            "Implementar monitoreo de seguridad continuo",
            "Establecer políticas de respuesta a incidentes",
            "Capacitar al personal en mejores prácticas de seguridad"
        ])
        
        return recommendations[:8]  # Limitar a 8 recomendaciones más relevantes
    
    def _extract_technical_terms(self, findings_list):
        """Extrae y explica términos técnicos encontrados"""
        findings_text = " ".join(findings_list).lower()
        terms = []
        
        technical_explanations = {
            "sql injection": "Técnica de ataque que permite insertar código SQL malicioso en aplicaciones web",
            "xss": "Cross-Site Scripting - Vulnerabilidad que permite ejecutar scripts maliciosos en navegadores",
            "csrf": "Cross-Site Request Forgery - Ataque que fuerza a usuarios a ejecutar acciones no deseadas",
            "ssl/tls": "Protocolos de seguridad que cifran comunicaciones entre cliente y servidor",
            "certificate": "Documento digital que verifica la identidad de un sitio web",
            "port scan": "Técnica para identificar puertos abiertos y servicios disponibles en un servidor",
            "banner grabbing": "Técnica para obtener información sobre servicios y versiones de software",
            "whois": "Servicio que proporciona información sobre dominios y direcciones IP registradas",
            "directory traversal": "Ataque que permite acceder a archivos fuera del directorio autorizado",
            "buffer overflow": "Vulnerabilidad que permite sobreescribir memoria para ejecutar código malicioso",
            "privilege escalation": "Técnica para obtener permisos administrativos no autorizados",
            "session hijacking": "Robo de identificadores de sesión para suplantar usuarios legítimos"
        }
        
        for term, explanation in technical_explanations.items():
            if term.replace('/', ' ').replace('-', ' ') in findings_text:
                terms.append(f"{term.upper()}: {explanation}")
        
        return terms
    
    def _create_comprehensive_report(self, findings_list, target_info):
        """Crea un reporte comprensivo y bien estructurado"""
        summary = self._generate_smart_summary(findings_list, target_info)
        risk = self._calculate_risk_level(findings_list)
        
        report = f"""
ANÁLISIS DE SEGURIDAD - REPORTE INTELIGENTE

RESUMEN EJECUTIVO:
{summary}

EVALUACIÓN DE RIESGO: {risk}
"""
        
        # Agregar contexto del riesgo
        risk_context = {
            "Alto": "Se requiere acción inmediata. Las vulnerabilidades encontradas pueden ser explotadas fácilmente.",
            "Medio": "Se recomienda corrección en el corto plazo. Existen riesgos que deben ser mitigados.",
            "Bajo": "Se sugiere revisión y mejoras. Los hallazgos representan oportunidades de fortalecimiento."
        }
        
        report += f"\n{risk_context.get(risk, '')}\n"
        
        # Hallazgos principales
        key_findings = self._extract_key_findings(findings_list)
        if key_findings:
            report += "\nHALLAZGOS PRINCIPALES:\n"
            for i, finding in enumerate(key_findings, 1):
                report += f"{i}. {finding}\n"
        
        # Vulnerabilidades
        vulnerabilities = self._extract_vulnerabilities_detailed(findings_list)
        if vulnerabilities:
            report += "\nVULNERABILIDADES IDENTIFICADAS:\n"
            for vuln in vulnerabilities:
                report += f"⚠️ {vuln}\n"
        
        # Recomendaciones prioritarias
        recommendations = self._generate_smart_recommendations(findings_list)
        if recommendations:
            report += "\nRECOMENDACIONES PRIORITARIAS:\n"
            for i, rec in enumerate(recommendations[:5], 1):
                priority = "🚨" if "CRÍTICO" in rec else "⚠️" if "URGENTE" in rec else "📋"
                report += f"{priority} {i}. {rec}\n"
        
        return report
    
    def _extract_key_findings(self, findings_list):
        """Extrae los hallazgos más importantes con contexto"""
        key_findings = []
        findings_text = " ".join(findings_list).lower()
        
        # Priorizar por severidad
        for finding in findings_list:
            finding_lower = finding.lower()
            
            # Vulnerabilidades críticas
            if any(keyword in finding_lower for keyword in self.risk_keywords["alto"]):
                context = self._add_finding_context(finding, "CRÍTICO")
                key_findings.append(context)
            # Problemas importantes
            elif any(keyword in finding_lower for keyword in self.risk_keywords["medio"]):
                context = self._add_finding_context(finding, "IMPORTANTE")
                key_findings.append(context)
        
        # Agregar otros hallazgos relevantes si hay pocos críticos
        if len(key_findings) < 5:
            for finding in findings_list:
                if not any(kf in finding for kf in [f.split(": ", 1)[-1] for f in key_findings]):
                    key_findings.append(finding)
                    if len(key_findings) >= 5:
                        break
        
        return key_findings[:5]
    
    def _add_finding_context(self, finding, priority):
        """Agrega contexto a un hallazgo específico"""
        finding_lower = finding.lower()
        
        if "sql" in finding_lower and "injection" in finding_lower:
            return f"{priority}: {finding} - Permite acceso no autorizado a bases de datos"
        elif "xss" in finding_lower:
            return f"{priority}: {finding} - Riesgo de ejecución de código malicioso en navegadores"
        elif "ssl" in finding_lower or "certificate" in finding_lower:
            return f"{priority}: {finding} - Comunicaciones potencialmente inseguras"
        elif "auth" in finding_lower or "login" in finding_lower:
            return f"{priority}: {finding} - Debilidades en control de acceso"
        else:
            return f"{priority}: {finding}"

# Clase principal que unifica ambos analizadores
class CyberScopeAnalyzer:
    def __init__(self, groq_api_key=None):
        """
        Inicializa el analizador principal de CyberScope
        
        Args:
            groq_api_key (str): API key de Groq (opcional)
        """
        self.groq_api_key = groq_api_key
        self.groq_analyzer = None
        self.fallback_analyzer = GroqFallbackAnalyzer()
        
        if groq_api_key:
            self.groq_analyzer = GroqAnalyzer(groq_api_key)
            logger.info("Analizador Groq inicializado")
        else:
            logger.info("Usando analizador inteligente de respaldo")
    
    def analyze_findings(self, findings_list, target_info=None):
        """
        Analiza hallazgos usando Groq API o analizador inteligente de respaldo
        
        Args:
            findings_list (list): Lista de hallazgos técnicos
            target_info (dict): Información del objetivo
            
        Returns:
            dict: Análisis estructurado
        """
        if not findings_list:
            logger.warning("No hay hallazgos para analizar")
            return None
        
        logger.info(f"Iniciando análisis de {len(findings_list)} hallazgos...")
        
        # Intentar con Groq primero
        if self.groq_analyzer:
            try:
                result = self.groq_analyzer.analyze_findings_with_groq(findings_list, target_info)
                if result:
                    logger.info("Análisis completado con Groq AI")
                    return result
                else:
                    logger.warning("Groq no disponible, usando analizador inteligente")
            except Exception as e:
                logger.error(f"Error con Groq, usando fallback: {e}")
        
        # Usar analizador inteligente de respaldo
        try:
            result = self.fallback_analyzer.analyze_findings_with_rules(findings_list, target_info)
            if result:
                logger.info("Análisis completado con analizador inteligente")
                return result
        except Exception as e:
            logger.error(f"Error en analizador de respaldo: {e}")
        
        return None

# Mantener compatibilidad con código existente
ChatGPTAnalyzer = GroqAnalyzer  # Alias para compatibilidad
ChatGPTFallbackAnalyzer = GroqFallbackAnalyzer  # Alias para compatibilidad
