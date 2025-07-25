import time
import json
import requests
from datetime import datetime
import re
from .utils import FINDINGS, logger

class ChatGPTAnalyzer:
    def __init__(self, api_key=None):
        """
        Inicializa el analizador de ChatGPT
        
        Args:
            api_key (str): API key de OpenAI (opcional, se puede usar variable de entorno)
        """
        self.api_key = api_key
        self.base_url = "https://api.openai.com/v1/chat/completions"
        
    def analyze_findings_with_chatgpt(self, findings_list, target_info=None):
        """
        Envía los hallazgos a ChatGPT para análisis y explicación
        
        Args:
            findings_list (list): Lista de hallazgos técnicos
            target_info (dict): Información del objetivo analizado
            
        Returns:
            dict: Análisis procesado por ChatGPT
        """
        try:
            # Preparar el prompt para ChatGPT
            prompt = self._create_analysis_prompt(findings_list, target_info)
            
            # Enviar a ChatGPT API
            response = self._send_to_chatgpt_api(prompt)
            
            if response:
                # Procesar respuesta para el usuario
                processed_analysis = self._process_chatgpt_response(response)
                
                # Agregar a findings
                FINDINGS.append(f"[CHATGPT_ANALYSIS] Análisis completado - {len(processed_analysis.get('key_points', []))} puntos clave identificados")
                
                return processed_analysis
            else:
                FINDINGS.append("[CHATGPT_ERROR] No se pudo obtener análisis de ChatGPT")
                return None
                
        except Exception as e:
            logger.error(f"Error en análisis ChatGPT: {e}")
            FINDINGS.append(f"[CHATGPT_ERROR] Error en análisis: {str(e)}")
            return None
    
    def _create_analysis_prompt(self, findings_list, target_info=None):
        """Crea el prompt para enviar a ChatGPT"""
        
        # Información del objetivo
        target_section = ""
        if target_info:
            target_section = f"""
INFORMACIÓN DEL OBJETIVO:
- URL/Host: {target_info.get('url', 'N/A')}
- Tipo de análisis: {', '.join(target_info.get('analysis_types', []))}
- Fecha: {target_info.get('timestamp', datetime.now().isoformat())}
"""
        
        # Hallazgos técnicos
        findings_text = "\n".join([f"- {finding}" for finding in findings_list[:50]])  # Limitar a 50 hallazgos
        
        prompt = f"""
Eres un experto en ciberseguridad y análisis forense digital. Analiza los siguientes hallazgos técnicos y proporciona una explicación clara y comprensible para usuarios no técnicos.

{target_section}

HALLAZGOS TÉCNICOS ENCONTRADOS:
{findings_text}

Por favor, proporciona un análisis que incluya:

1. RESUMEN EJECUTIVO (2-3 líneas): Explicación simple de qué se encontró
2. NIVEL DE RIESGO: Bajo/Medio/Alto con justificación
3. HALLAZGOS PRINCIPALES: Los 5 hallazgos más importantes explicados en lenguaje simple
4. VULNERABILIDADES IDENTIFICADAS: Problemas de seguridad encontrados
5. RECOMENDACIONES: Acciones específicas a tomar
6. TÉRMINOS TÉCNICOS: Explicación de conceptos técnicos mencionados

Usa un lenguaje claro y evita jerga técnica. Si usas términos técnicos, explícalos inmediatamente.
"""
        
        return prompt
    
    def _send_to_chatgpt_api(self, prompt):
        """
        Envía el prompt a la API de ChatGPT
        
        Args:
            prompt (str): Prompt a enviar
            
        Returns:
            str: Respuesta de ChatGPT o None si hay error
        """
        if not self.api_key:
            logger.warning("No se proporcionó API key de OpenAI")
            return None
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {
                    "role": "system",
                    "content": "Eres un experto en ciberseguridad que explica hallazgos técnicos de forma clara para usuarios no técnicos."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": 2000,
            "temperature": 0.3
        }
        
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                return result['choices'][0]['message']['content']
            else:
                logger.error(f"Error API ChatGPT: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error enviando a ChatGPT API: {e}")
            return None
    
    def _process_chatgpt_response(self, response_text):
        """
        Procesa la respuesta de ChatGPT para estructurarla
        
        Args:
            response_text (str): Respuesta cruda de ChatGPT
            
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
            "simplified_text": response_text
        }
        
        try:
            # Extraer secciones usando regex
            sections = {
                "executive_summary": r"RESUMEN EJECUTIVO[:\s]*(.+?)(?=\n\d+\.|NIVEL DE RIESGO|$)",
                "risk_level": r"NIVEL DE RIESGO[:\s]*(.+?)(?=\n\d+\.|HALLAZGOS|$)",
                "key_findings": r"HALLAZGOS PRINCIPALES[:\s]*(.+?)(?=\n\d+\.|VULNERABILIDADES|$)",
                "vulnerabilities": r"VULNERABILIDADES IDENTIFICADAS[:\s]*(.+?)(?=\n\d+\.|RECOMENDACIONES|$)",
                "recommendations": r"RECOMENDACIONES[:\s]*(.+?)(?=\n\d+\.|TÉRMINOS|$)",
                "technical_terms": r"TÉRMINOS TÉCNICOS[:\s]*(.+?)$"
            }
            
            for section, pattern in sections.items():
                match = re.search(pattern, response_text, re.DOTALL | re.IGNORECASE)
                if match:
                    content = match.group(1).strip()
                    
                    if section in ["key_findings", "vulnerabilities", "recommendations", "technical_terms"]:
                        # Convertir a lista
                        items = [item.strip() for item in re.split(r'\n[-•]\s*', content) if item.strip()]
                        processed[section] = items
                    else:
                        processed[section] = content
            
            # Extraer nivel de riesgo específico
            risk_match = re.search(r'\b(Bajo|Medio|Alto)\b', processed.get("risk_level", ""), re.IGNORECASE)
            if risk_match:
                processed["risk_level"] = risk_match.group(1).capitalize()
            
        except Exception as e:
            logger.error(f"Error procesando respuesta ChatGPT: {e}")
        
        return processed

class ChatGPTFallbackAnalyzer:
    """
    Analizador de respaldo que funciona sin API de ChatGPT
    Proporciona análisis básico usando reglas predefinidas
    """
    
    def __init__(self):
        self.risk_keywords = {
            "alto": ["sql injection", "xss", "command injection", "directory traversal", "rce", "authentication bypass"],
            "medio": ["information disclosure", "weak ssl", "missing headers", "outdated", "vulnerable"],
            "bajo": ["banner", "version", "port open", "whois", "dns"]
        }
    
    def analyze_findings_with_rules(self, findings_list, target_info=None):
        """
        Analiza hallazgos usando reglas predefinidas
        
        Args:
            findings_list (list): Lista de hallazgos
            target_info (dict): Información del objetivo
            
        Returns:
            dict: Análisis básico estructurado
        """
        try:
            # Análisis básico
            analysis = {
                "timestamp": datetime.now().isoformat(),
                "executive_summary": self._generate_summary(findings_list),
                "risk_level": self._calculate_risk_level(findings_list),
                "key_findings": self._extract_key_findings(findings_list),
                "vulnerabilities": self._extract_vulnerabilities(findings_list),
                "recommendations": self._generate_recommendations(findings_list),
                "technical_terms": self._extract_technical_terms(findings_list),
                "simplified_text": self._create_simplified_report(findings_list)
            }
            
            FINDINGS.append(f"[FALLBACK_ANALYSIS] Análisis básico completado - Riesgo: {analysis['risk_level']}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error en análisis de respaldo: {e}")
            return None
    
    def _generate_summary(self, findings_list):
        """Genera un resumen ejecutivo básico"""
        total_findings = len(findings_list)
        vuln_count = len([f for f in findings_list if any(keyword in f.lower() for keyword in self.risk_keywords["alto"] + self.risk_keywords["medio"])])
        
        if vuln_count > 5:
            return f"Se encontraron {total_findings} hallazgos, incluyendo {vuln_count} posibles vulnerabilidades que requieren atención inmediata."
        elif vuln_count > 0:
            return f"Se identificaron {total_findings} hallazgos con {vuln_count} problemas de seguridad que deben ser revisados."
        else:
            return f"Análisis completado con {total_findings} hallazgos. No se detectaron vulnerabilidades críticas evidentes."
    
    def _calculate_risk_level(self, findings_list):
        """Calcula el nivel de riesgo basado en palabras clave"""
        findings_text = " ".join(findings_list).lower()
        
        high_risk_count = sum(1 for keyword in self.risk_keywords["alto"] if keyword in findings_text)
        medium_risk_count = sum(1 for keyword in self.risk_keywords["medio"] if keyword in findings_text)
        
        if high_risk_count > 0:
            return "Alto"
        elif medium_risk_count > 2:
            return "Medio"
        else:
            return "Bajo"
    
    def _extract_key_findings(self, findings_list):
        """Extrae los hallazgos más importantes"""
        key_findings = []
        
        # Priorizar vulnerabilidades
        for finding in findings_list:
            if any(keyword in finding.lower() for keyword in self.risk_keywords["alto"]):
                key_findings.append(f"CRÍTICO: {finding}")
            elif any(keyword in finding.lower() for keyword in self.risk_keywords["medio"]):
                key_findings.append(f"IMPORTANTE: {finding}")
        
        # Agregar otros hallazgos relevantes si hay pocos
        if len(key_findings) < 5:
            for finding in findings_list:
                if finding not in [kf.split(": ", 1)[-1] for kf in key_findings]:
                    key_findings.append(finding)
                    if len(key_findings) >= 5:
                        break
        
        return key_findings[:5]
    
    def _extract_vulnerabilities(self, findings_list):
        """Extrae vulnerabilidades específicas"""
        vulnerabilities = []
        
        for finding in findings_list:
            finding_lower = finding.lower()
            if "sql" in finding_lower and "injection" in finding_lower:
                vulnerabilities.append("Posible inyección SQL detectada - Permite acceso no autorizado a bases de datos")
            elif "xss" in finding_lower:
                vulnerabilities.append("Cross-Site Scripting (XSS) - Permite ejecutar código malicioso en navegadores")
            elif "command injection" in finding_lower:
                vulnerabilities.append("Inyección de comandos - Permite ejecutar comandos del sistema")
            elif "directory traversal" in finding_lower:
                vulnerabilities.append("Directory Traversal - Permite acceso a archivos del sistema")
            elif "ssl" in finding_lower and ("weak" in finding_lower or "expired" in finding_lower):
                vulnerabilities.append("Problemas de certificado SSL - Comunicación insegura")
        
        return vulnerabilities
    
    def _generate_recommendations(self, findings_list):
        """Genera recomendaciones básicas"""
        recommendations = [
            "Revisar y corregir todas las vulnerabilidades identificadas",
            "Implementar cabeceras de seguridad faltantes",
            "Actualizar software y componentes desactualizados",
            "Realizar pruebas de penetración regulares",
            "Implementar monitoreo de seguridad continuo"
        ]
        
        return recommendations
    
    def _extract_technical_terms(self, findings_list):
        """Extrae y explica términos técnicos"""
        terms = []
        findings_text = " ".join(findings_list).lower()
        
        technical_explanations = {
            "sql injection": "Técnica que permite insertar código SQL malicioso en aplicaciones web",
            "xss": "Cross-Site Scripting - Vulnerabilidad que permite ejecutar scripts en navegadores",
            "ssl": "Secure Sockets Layer - Protocolo de seguridad para comunicaciones web",
            "whois": "Servicio que proporciona información sobre dominios registrados",
            "port scan": "Técnica para identificar puertos abiertos en un servidor",
            "banner": "Información que revela un servicio sobre su versión o configuración"
        }
        
        for term, explanation in technical_explanations.items():
            if term in findings_text:
                terms.append(f"{term.upper()}: {explanation}")
        
        return terms
    
    def _create_simplified_report(self, findings_list):
        """Crea un reporte simplificado"""
        summary = self._generate_summary(findings_list)
        risk = self._calculate_risk_level(findings_list)
        
        report = f"""
ANÁLISIS DE SEGURIDAD - REPORTE SIMPLIFICADO

RESUMEN: {summary}

NIVEL DE RIESGO: {risk}

HALLAZGOS PRINCIPALES:
"""
        
        key_findings = self._extract_key_findings(findings_list)
        for i, finding in enumerate(key_findings, 1):
            report += f"{i}. {finding}\n"
        
        vulnerabilities = self._extract_vulnerabilities(findings_list)
        if vulnerabilities:
            report += "\nVULNERABILIDADES IDENTIFICADAS:\n"
            for vuln in vulnerabilities:
                report += f"• {vuln}\n"
        
        recommendations = self._generate_recommendations(findings_list)
        report += "\nRECOMENDACIONES:\n"
        for rec in recommendations:
            report += f"• {rec}\n"
        
        return report