#!/usr/bin/env python3
"""
Sistema de Análisis Forense Remoto SSH - CyberScope v2.0 - CORREGIDO
Análisis forense sin rastros en servidores remotos + Análisis IA con Groq
"""

import os
import subprocess
import json
import hashlib
import uuid
from datetime import datetime
from pathlib import Path
import time
import socket
import threading
from typing import Dict, List, Optional, Tuple

from .utils import FINDINGS, logger
from .remote_config import RemoteForensicConfig

# === GROQ INTEGRATION ===
try:
    from groq import Groq
    GROQ_DISPONIBLE = True
except ImportError:
    GROQ_DISPONIBLE = False
    logger.warning("Groq no está instalado. Análisis IA no disponible para forensics remotos")

class RemoteForensicScanner:
    """Scanner forense remoto que no deja rastros en el servidor objetivo + Análisis IA"""
    
    def __init__(self, config: Dict = None):
        """
        Inicializa el scanner forense remoto
        
        Args:
            config (Dict): Configuración del scanner
        """
        self.config = config or {}
        self.session_id = str(uuid.uuid4())[:8]
        self.evidence_chain = []
        self.start_time = datetime.now()
        
        # Configuración SSH con valores por defecto seguros
        self.ssh_timeout = self.config.get('ssh_timeout', 50)
        self.max_concurrent = self.config.get('max_concurrent', 3)
        self.evidence_dir = self.config.get('evidence_dir', './forensic_evidence')
        
        # Crear directorio de evidencia
        os.makedirs(self.evidence_dir, exist_ok=True)
        
        # Verificar disponibilidad de Groq
        self.groq_available = self._check_groq_availability()
        
        logger.info(f"Scanner forense remoto inicializado - Sesión: {self.session_id}")
        logger.info(f"Análisis IA forense: {'✅ Disponible' if self.groq_available else '❌ No disponible'}")
        FINDINGS.append(f"[REMOTE_INIT] Sesión forense iniciada: {self.session_id}")
        if self.groq_available:
            FINDINGS.append("[REMOTE_AI] ✅ Análisis IA forense habilitado")
    
    def _check_groq_availability(self) -> bool:
        """Verifica si Groq está disponible y configurado"""
        if not GROQ_DISPONIBLE:
            return False
        
        api_key = os.getenv('GROQ_API_KEY')
        if not api_key or not api_key.startswith('gsk_'):
            logger.warning("GROQ_API_KEY no configurada correctamente para análisis forense")
            return False
        
        return True
    
    def _generate_forensic_ai_analysis(self, evidence_data: Dict, analysis_type: str = "comprehensive") -> str:
        """
        Genera análisis IA profesional de evidencia forense
        
        Args:
            evidence_data: Datos de evidencia recopilados
            analysis_type: Tipo de análisis ("quick", "comprehensive", "vulnerability")
            
        Returns:
            str: Análisis IA profesional
        """
        if not self.groq_available:
            return "⚠️ Análisis IA forense no disponible - Groq no configurado"
        
        try:
            client = Groq(api_key=os.getenv('GROQ_API_KEY'))
            
            # Preparar evidencia para análisis
            formatted_evidence = self._format_evidence_for_ai(evidence_data)
            
            # Seleccionar prompt según tipo de análisis
            if analysis_type == "quick":
                prompt = self._get_quick_analysis_prompt(formatted_evidence)
            elif analysis_type == "vulnerability":
                prompt = self._get_vulnerability_analysis_prompt(formatted_evidence)
            else:
                prompt = self._get_comprehensive_analysis_prompt(formatted_evidence)
            
            logger.info(f"🤖 Generando análisis IA forense: {analysis_type}")
            
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "Eres un experto forense digital y consultor senior en ciberseguridad especializado en análisis de sistemas Linux/Unix. Proporciona análisis profesionales, precisos y actionables."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                model="llama-3.1-70b-versatile",
                max_tokens=2000,
                temperature=0.3
            )
            
            analysis = chat_completion.choices[0].message.content
            logger.info(f"✅ Análisis IA forense generado: {len(analysis)} caracteres")
            return analysis
            
        except Exception as e:
            logger.error(f"💥 Error en análisis IA forense: {e}")
            return f"⚠️ Error en análisis IA forense: {str(e)}"
    
    def _format_evidence_for_ai(self, evidence_data: Dict) -> str:
        """Formatea la evidencia para análisis IA"""
        formatted = []
        
        for category, data in evidence_data.items():
            formatted.append(f"\n=== {category.upper()} ===")
            
            if isinstance(data, dict):
                if "vulnerabilities_found" in data:
                    # Formato para análisis de vulnerabilidades
                    if data["vulnerabilities_found"]:
                        formatted.append("VULNERABILIDADES ENCONTRADAS:")
                        for vuln in data["vulnerabilities_found"]:
                            formatted.append(f"- {vuln}")
                    
                    if "evidence" in data:
                        formatted.append("EVIDENCIA:")
                        for key, evidence in data["evidence"].items():
                            if isinstance(evidence, dict) and "output" in evidence:
                                output_preview = evidence["output"][:200]
                                formatted.append(f"{key}: {output_preview}...")
                else:
                    # Formato para evidencia general
                    for key, value in data.items():
                        if isinstance(value, dict) and "output" in value:
                            output_preview = value["output"][:200]
                            formatted.append(f"{key}: {output_preview}...")
                        else:
                            formatted.append(f"{key}: {str(value)[:100]}...")
        
        return "\n".join(formatted)
    
    def _get_quick_analysis_prompt(self, evidence: str) -> str:
        """Prompt para análisis rápido"""
        return f"""
Analiza la siguiente evidencia forense de un escaneo rápido y proporciona:

1. RESUMEN EJECUTIVO (3-4 líneas)
2. HALLAZGOS PRINCIPALES (máximo 5 puntos)
3. NIVEL DE RIESGO: [Crítico/Alto/Medio/Bajo/Informativo]
4. ACCIONES INMEDIATAS RECOMENDADAS (máximo 3)

EVIDENCIA FORENSE:
{evidence}

Responde en español, de forma concisa y profesional. Enfócate en los hallazgos más importantes para la seguridad.
"""
    
    def _get_comprehensive_analysis_prompt(self, evidence: str) -> str:
        """Prompt para análisis comprehensivo"""
        return f"""
Realiza un análisis forense digital completo de la siguiente evidencia y proporciona:

1. RESUMEN EJECUTIVO
2. ANÁLISIS POR CATEGORÍAS:
   - Identificación del Sistema
   - Actividad de Usuarios
   - Procesos y Servicios
   - Configuración de Red
   - Sistema de Archivos
   - Configuración de Seguridad

3. HALLAZGOS DE SEGURIDAD CRÍTICOS
4. INDICADORES DE COMPROMISO (IoCs)
5. RECOMENDACIONES FORENSES ESPECÍFICAS
6. NIVEL DE RIESGO GENERAL

EVIDENCIA FORENSE:
{evidence}

Proporciona un análisis detallado y profesional en español, como lo haría un experto forense digital.
"""
    
    def _get_vulnerability_analysis_prompt(self, evidence: str) -> str:
        """Prompt para análisis de vulnerabilidades"""
        return f"""
Analiza las siguientes vulnerabilidades encontradas en el sistema y proporciona:

1. RESUMEN DE VULNERABILIDADES
2. CLASIFICACIÓN POR CRITICIDAD:
   - CRÍTICAS (Explotación inmediata)
   - ALTAS (Requieren atención urgente)
   - MEDIAS (Deben ser corregidas)
   - BAJAS (Buenas prácticas)

3. VECTORES DE ATAQUE POTENCIALES
4. PLAN DE REMEDIACIÓN PRIORIZADO
5. MEDIDAS DE MITIGACIÓN INMEDIATAS

EVIDENCIA DE VULNERABILIDADES:
{evidence}

Responde como un consultor senior en ciberseguridad, en español, con recomendaciones específicas y actionables.
"""

    # === TU CÓDIGO ORIGINAL CON MEJORAS ===
    
    def test_ssh_connection(self, hostname: str, username: str, key_file: str = None, 
                           port: int = 22, password: str = None) -> bool:
        """
        Prueba la conexión SSH antes del análisis completo
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            key_file: Archivo de clave privada (opcional)
            port: Puerto SSH
            password: Contraseña SSH (opcional)
            
        Returns:
            bool: True si la conexión es exitosa
        """
        logger.info(f"Probando conexión SSH a {hostname}:{port} como {username}")
        
        try:
            # Primero verificar conectividad básica
            if not self._test_network_connectivity(hostname, port):
                return False
            
            # Construir comando SSH de prueba
            ssh_cmd = self._build_ssh_command(hostname, username, key_file, port, password)
            ssh_cmd.append('echo "SSH_TEST_OK"')
            
            logger.debug(f"Ejecutando test SSH...")
            
            # Ejecutar comando de prueba
            stdout, stderr, return_code = self._execute_ssh_command(
                ssh_cmd, password, timeout=self.ssh_timeout
            )
            
            if return_code == 0 and "SSH_TEST_OK" in stdout:
                logger.info(f"✅ Conexión SSH exitosa a {hostname}:{port}")
                FINDINGS.append(f"[SSH_TEST] Conexión exitosa a {hostname}:{port}")
                return True
            else:
                logger.error(f"❌ Fallo en prueba SSH a {hostname}:{port}")
                logger.error(f"Error: {stderr}")
                FINDINGS.append(f"[SSH_ERROR] Fallo de conexión: {stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"⏰ Timeout en conexión SSH a {hostname}:{port}")
            FINDINGS.append(f"[SSH_TIMEOUT] Timeout conectando a {hostname}:{port}")
            return False
        except Exception as e:
            logger.error(f"💥 Error en prueba SSH: {e}")
            FINDINGS.append(f"[SSH_ERROR] Error de conexión: {str(e)}")
            return False
    
    def _test_network_connectivity(self, hostname: str, port: int) -> bool:
        """Prueba conectividad de red básica"""
        try:
            logger.debug(f"🌐 Probando conectividad de red a {hostname}:{port}")
            
            # Test de conectividad TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((hostname, port))
            sock.close()
            
            if result == 0:
                logger.info(f"✅ Puerto {port} accesible en {hostname}")
                return True
            else:
                logger.error(f"❌ Puerto {port} no accesible en {hostname}")
                FINDINGS.append(f"[NETWORK_ERROR] Puerto {port} no accesible en {hostname}")
                return False
                
        except Exception as e:
            logger.error(f"💥 Error en test de conectividad: {e}")
            FINDINGS.append(f"[NETWORK_ERROR] Error de conectividad: {str(e)}")
            return False
    
    def _build_ssh_command(self, hostname: str, username: str, key_file: str = None, 
                          port: int = 22, password: str = None) -> List[str]:
        """
        Construye el comando SSH con las opciones apropiadas
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            key_file: Archivo de clave privada
            port: Puerto SSH
            password: Contraseña SSH
            
        Returns:
            List[str]: Comando SSH como lista
        """
        # Determinar método de autenticación
        auth_method = self._determine_auth_method(key_file, password)
        logger.info(f"🔐 Método de autenticación: {auth_method}")
        
        if auth_method == "key":
            return self._build_key_auth_command(hostname, username, key_file, port)
        elif auth_method == "password":
            return self._build_password_auth_command(hostname, username, password, port)
        else:
            raise ValueError("No se pudo determinar método de autenticación válido")
    
    def _determine_auth_method(self, key_file: str = None, password: str = None) -> str:
        """Determina el método de autenticación a usar"""
        if key_file and key_file.strip():
            if os.path.exists(key_file.strip()):
                return "key"
            else:
                logger.warning(f"⚠️ Archivo de clave no encontrado: {key_file}")
                if password and password.strip():
                    logger.info("🔄 Cambiando a autenticación por contraseña")
                    return "password"
                else:
                    raise FileNotFoundError(f"Archivo de clave no encontrado: {key_file}")
        elif password and password.strip():
            return "password"
        else:
            raise ValueError("Debe proporcionar clave privada O contraseña")
    
    def _build_key_auth_command(self, hostname: str, username: str, key_file: str, port: int) -> List[str]:
        """Construir comando SSH para autenticación por clave"""
        logger.debug(f"🔑 Construyendo comando SSH con clave privada: {key_file}")
        
        # Verificar permisos del archivo de clave
        self._check_key_permissions(key_file)
        
        ssh_cmd = [
            'ssh',
            '-o', f'ConnectTimeout={self.ssh_timeout}',
            '-o', 'ServerAliveInterval=60',
            '-o', 'ServerAliveCountMax=3',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-o', 'BatchMode=yes',  # No solicitar contraseña
            '-o', 'PasswordAuthentication=no',  # Forzar uso de clave
            '-i', key_file.strip(),
            '-p', str(port),
            f"{username}@{hostname}"
        ]
        
        return ssh_cmd
    
    def _build_password_auth_command(self, hostname: str, username: str, password: str, port: int) -> List[str]:
        """Construir comando SSH para autenticación por contraseña"""
        logger.debug("🔒 Construyendo comando SSH con contraseña")
        
        # Verificar que sshpass esté disponible
        if not self._check_sshpass_available():
            raise RuntimeError("sshpass no está disponible y es requerido para autenticación por contraseña")
        
        ssh_cmd = [
            'sshpass', '-p', password,
            'ssh',
            '-o', f'ConnectTimeout={self.ssh_timeout}',
            '-o', 'ServerAliveInterval=60',
            '-o', 'ServerAliveCountMax=3',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-o', 'BatchMode=yes',
            '-o', 'PasswordAuthentication=yes',
            '-p', str(port),
            f"{username}@{hostname}"
        ]
        
        return ssh_cmd
    
    def _check_key_permissions(self, key_file: str):
        """Verificar y corregir permisos del archivo de clave"""
        try:
            stat_info = os.stat(key_file)
            mode = oct(stat_info.st_mode)[-3:]
            
            if mode != '600':
                logger.warning(f"⚠️ Archivo de clave tiene permisos inseguros: {mode}")
                try:
                    os.chmod(key_file, 0o600)
                    logger.info(f"✅ Permisos del archivo de clave corregidos a 600")
                except OSError as e:
                    logger.warning(f"⚠️ No se pudieron corregir permisos: {e}")
            
        except OSError as e:
            logger.warning(f"⚠️ No se pudieron verificar permisos del archivo de clave: {e}")
    
    def _check_sshpass_available(self) -> bool:
        """Verifica si sshpass está disponible"""
        try:
            result = subprocess.run(['which', 'sshpass'], capture_output=True, timeout=10)
            available = result.returncode == 0
            if available:
                logger.debug("✅ sshpass está disponible")
            else:
                logger.error("❌ sshpass NO está disponible")
            return available
        except Exception as e:
            logger.error(f"💥 Error verificando sshpass: {e}")
            return False
    
    def _execute_ssh_command(self, ssh_cmd: List[str], password: str = None, timeout: int = 30) -> Tuple[str, str, int]:
        """
        Ejecuta un comando SSH y retorna el resultado
        
        Args:
            ssh_cmd: Comando SSH como lista
            password: Contraseña (solo para logging, ya está en el comando)
            timeout: Timeout en segundos
            
        Returns:
            Tuple[str, str, int]: (stdout, stderr, return_code)
        """
        try:
            logger.debug(f"🚀 Ejecutando comando SSH (timeout: {timeout}s)")
            
            # Ejecutar comando
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=dict(os.environ, LC_ALL='C')  # Asegurar salida en inglés
            )
            
            logger.debug(f"📊 SSH ejecutado - Return code: {result.returncode}")
            if result.returncode != 0:
                logger.debug(f"⚠️ SSH stderr: {result.stderr[:200]}...")
            
            return result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired as e:
            error_msg = f"Timeout ejecutando comando SSH después de {timeout}s"
            logger.error(f"⏰ {error_msg}")
            return "", error_msg, -1
        except Exception as e:
            error_msg = f"Error ejecutando comando SSH: {str(e)}"
            logger.error(f"💥 {error_msg}")
            return "", error_msg, -1
    
    def _execute_remote_command(self, hostname: str, username: str, command: str,
                               key_file: str = None, port: int = 22, 
                               password: str = None, timeout: int = 30) -> Tuple[str, str, int]:
        """
        Ejecuta un comando remoto por SSH
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            command: Comando a ejecutar
            key_file: Archivo de clave privada
            port: Puerto SSH
            password: Contraseña SSH
            timeout: Timeout en segundos
            
        Returns:
            Tuple[str, str, int]: (stdout, stderr, return_code)
        """
        try:
            # Construir comando SSH completo
            ssh_cmd = self._build_ssh_command(hostname, username, key_file, port, password)
            ssh_cmd.append(command)
            
            logger.debug(f"🔧 Ejecutando comando remoto: {command[:50]}...")
            
            # Ejecutar comando
            stdout, stderr, return_code = self._execute_ssh_command(ssh_cmd, password, timeout)
            
            # Registrar evidencia
            self._record_evidence(hostname, command, stdout, stderr, return_code)
            
            if return_code == 0:
                logger.debug(f"✅ Comando ejecutado exitosamente")
            else:
                logger.warning(f"⚠️ Comando falló con código: {return_code}")
            
            return stdout, stderr, return_code
            
        except Exception as e:
            error_msg = f"Error ejecutando comando remoto: {str(e)}"
            logger.error(f"💥 {error_msg}")
            FINDINGS.append(f"[CMD_ERROR] {error_msg}")
            return "", error_msg, -1
    
    def _record_evidence(self, hostname: str, command: str, stdout: str, 
                        stderr: str, return_code: int):
        """Registra evidencia de comandos ejecutados"""
        evidence_entry = {
            "timestamp": datetime.now().isoformat(),
            "hostname": hostname,
            "command": command,
            "return_code": return_code,
            "stdout_hash": hashlib.sha256(stdout.encode()).hexdigest(),
            "stderr_hash": hashlib.sha256(stderr.encode()).hexdigest(),
            "session_id": self.session_id
        }
        
        self.evidence_chain.append(evidence_entry)
        logger.debug(f"📝 Evidencia registrada para comando: {command[:30]}...")
    
    def quick_scan(self, hostname: str, username: str, key_file: str = None, 
                   port: int = 22, password: str = None) -> Dict:
        """
        Escaneo rápido del sistema remoto + Análisis IA
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            key_file: Archivo de clave privada
            port: Puerto SSH
            password: Contraseña SSH
            
        Returns:
            Dict: Evidencia recopilada + análisis IA
        """
        logger.info(f"🚀 Iniciando escaneo rápido de {hostname}")
        FINDINGS.append(f"[QUICK_SCAN] Iniciando escaneo rápido de {hostname}")
        
        evidence = {}
        
        # Comandos básicos para escaneo rápido
        quick_commands = {
            "system_info": "uname -a && hostname && whoami && id",
            "uptime": "uptime",
            "users": "who && last | head -10",
            "processes": "ps aux | head -20",
            "network": "netstat -tupln 2>/dev/null | head -10 || ss -tupln 2>/dev/null | head -10",
            "disk_usage": "df -h",
            "memory": "free -h"
        }
        
        success_count = 0
        total_commands = len(quick_commands)
        
        for category, command in quick_commands.items():
            try:
                logger.debug(f"📋 Ejecutando: {category}")
                
                stdout, stderr, return_code = self._execute_remote_command(
                    hostname, username, command, key_file, port, password, timeout=30
                )
                
                if return_code == 0 and stdout.strip():
                    evidence[category] = {
                        "command": command,
                        "output": stdout.strip(),
                        "timestamp": datetime.now().isoformat()
                    }
                    success_count += 1
                    logger.debug(f"✅ {category}: {len(stdout)} bytes recopilados")
                    FINDINGS.append(f"[QUICK_EVIDENCE] {category}: {len(stdout)} bytes recopilados")
                else:
                    logger.warning(f"⚠️ {category}: Sin datos o error - {stderr[:100]}")
                    FINDINGS.append(f"[QUICK_WARNING] {category}: Sin datos válidos")
                    
            except Exception as e:
                logger.error(f"💥 Error en comando {category}: {e}")
                FINDINGS.append(f"[QUICK_ERROR] Error en {category}: {str(e)}")
        
        logger.info(f"✅ Escaneo rápido completado: {success_count}/{total_commands} comandos exitosos")
        FINDINGS.append(f"[QUICK_COMPLETE] Escaneo rápido completado: {success_count}/{total_commands} comandos exitosos")
        
        # === ANÁLISIS IA AGREGADO ===
        if evidence and self.groq_available:
            logger.info("🤖 Generando análisis IA del escaneo rápido...")
            ai_analysis = self._generate_forensic_ai_analysis(evidence, "quick")
            evidence["ai_analysis"] = {
                "analysis": ai_analysis,
                "generated_at": datetime.now().isoformat(),
                "type": "quick_scan"
            }
            FINDINGS.append("[QUICK_AI] ✅ Análisis IA del escaneo rápido generado")
        
        return evidence
    
    def comprehensive_system_analysis(self, hostname: str, username: str, 
                                    key_file: str = None, port: int = 22, 
                                    password: str = None) -> Dict:
        """
        Análisis forense completo del sistema + Análisis IA
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            key_file: Archivo de clave privada
            port: Puerto SSH
            password: Contraseña SSH
            
        Returns:
            Dict: Evidencia forense completa + análisis IA
        """
        logger.info(f"🔍 Iniciando análisis forense completo de {hostname}")
        FINDINGS.append(f"[FORENSIC_ANALYSIS] Iniciando análisis completo de {hostname}")
        
        evidence = {}
        
        # Comandos forenses organizados por categoría
        forensic_commands = {
            "system_identification": {
                "os_info": "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || uname -a",
                "kernel": "uname -r && cat /proc/version 2>/dev/null",
                "hostname": "hostname && cat /etc/hostname 2>/dev/null",
                "timezone": "date && timedatectl 2>/dev/null || cat /etc/timezone 2>/dev/null"
            },
            
            "user_activity": {
                "current_users": "who && w",
                "login_history": "last | head -20",
                "failed_logins": "lastb 2>/dev/null | head -10 || echo 'lastb not available'",
                "user_accounts": "cat /etc/passwd | grep -v nologin | grep -v false",
                "sudo_users": "getent group sudo 2>/dev/null || getent group wheel 2>/dev/null"
            },
            
            "process_analysis": {
                "running_processes": "ps auxf",
                "process_tree": "pstree -p 2>/dev/null || ps auxf",
                "listening_services": "netstat -tupln 2>/dev/null || ss -tupln 2>/dev/null",
                "cron_jobs": "crontab -l 2>/dev/null && ls -la /etc/cron* 2>/dev/null"
            },
            
            "network_forensics": {
                "network_config": "ip addr show 2>/dev/null || ifconfig -a 2>/dev/null",
                "routing_table": "ip route 2>/dev/null || route -n 2>/dev/null",
                "arp_table": "arp -a 2>/dev/null || ip neigh 2>/dev/null",
                "firewall_rules": "iptables -L -n 2>/dev/null || ufw status 2>/dev/null"
            },
            
            "file_system": {
                "mounted_filesystems": "mount && df -h",
                "recent_files": "find /tmp /var/tmp -type f -mtime -1 2>/dev/null | head -20",
                "suid_files": "find / -perm -4000 2>/dev/null | head -20",
                "world_writable": "find / -type f -perm -002 2>/dev/null | head -10"
            },
            
            "security_config": {
                "ssh_config": "cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$'",
                "installed_packages": "dpkg -l 2>/dev/null | head -20 || rpm -qa 2>/dev/null | head -20",
                "services": "systemctl list-units --type=service --state=running 2>/dev/null | head -15"
            }
        }
        
        total_categories = len(forensic_commands)
        completed_categories = 0
        
        for category, commands in forensic_commands.items():
            evidence[category] = {}
            logger.info(f"📂 Analizando categoría: {category}")
            FINDINGS.append(f"[FORENSIC_CATEGORY] Analizando: {category}")
            
            success_count = 0
            total_commands = len(commands)
            
            for subcategory, command in commands.items():
                try:
                    stdout, stderr, return_code = self._execute_remote_command(
                        hostname, username, command, key_file, port, password, timeout=45
                    )
                    
                    if return_code == 0 and stdout.strip():
                        evidence[category][subcategory] = {
                            "command": command,
                            "output": stdout.strip(),
                            "timestamp": datetime.now().isoformat(),
                            "hash": hashlib.sha256(stdout.encode()).hexdigest()
                        }
                        success_count += 1
                        logger.debug(f"✅ {subcategory}: {len(stdout)} bytes")
                        FINDINGS.append(f"[FORENSIC_EVIDENCE] {subcategory}: {len(stdout)} bytes")
                    else:
                        logger.debug(f"⚠️ {subcategory}: Sin datos válidos")
                        FINDINGS.append(f"[FORENSIC_WARNING] {subcategory}: Sin datos o error")
                        
                except Exception as e:
                    logger.error(f"💥 Error en {subcategory}: {e}")
                    FINDINGS.append(f"[FORENSIC_ERROR] {subcategory}: {str(e)}")
            
            completed_categories += 1
            logger.info(f"📊 Categoría {category} completada: {success_count}/{total_commands} comandos exitosos")
        
        logger.info(f"🎯 Análisis forense completado: {completed_categories}/{total_categories} categorías procesadas")
        FINDINGS.append(f"[FORENSIC_COMPLETE] Análisis forense completado: {len(evidence)} categorías")
        
        # === ANÁLISIS IA AGREGADO ===
        if evidence and self.groq_available:
            logger.info("🤖 Generando análisis IA forense completo...")
            ai_analysis = self._generate_forensic_ai_analysis(evidence, "comprehensive")
            evidence["ai_analysis"] = {
                "analysis": ai_analysis,
                "generated_at": datetime.now().isoformat(),
                "type": "comprehensive_analysis"
            }
            FINDINGS.append("[FORENSIC_AI] ✅ Análisis IA forense completo generado")
        
        return evidence
    
    def vulnerability_assessment(self, hostname: str, username: str, 
                               key_file: str = None, port: int = 22, 
                               password: str = None) -> Dict:
        """
        Evaluación de vulnerabilidades del sistema remoto + Análisis IA
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            key_file: Archivo de clave privada
            port: Puerto SSH
            password: Contraseña SSH
            
        Returns:
            Dict: Vulnerabilidades encontradas + análisis IA
        """
        logger.info(f"🛡️ Iniciando evaluación de vulnerabilidades en {hostname}")
        FINDINGS.append(f"[VULN_ASSESSMENT] Iniciando evaluación de vulnerabilidades")
        
        vulnerabilities = {}
        
        # Categorías de vulnerabilidades a evaluar
        vuln_checks = {
            "ssh_security": {
                "ssh_version": "ssh -V 2>&1",
                "ssh_config_check": "cat /etc/ssh/sshd_config 2>/dev/null | grep -E '(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|Protocol)'",
                "ssh_keys": "ls -la ~/.ssh/ 2>/dev/null"
            },
            
            "privilege_escalation": {
                "sudo_config": "sudo -l 2>/dev/null || echo 'sudo not available'",
                "suid_binaries": "find / -perm -4000 2>/dev/null | head -20",
                "writable_etc": "find /etc -writable 2>/dev/null | head -10",
                "kernel_version": "uname -r && cat /proc/version 2>/dev/null"
            },
            
            "web_vulnerabilities": {
                "web_servers": "ps aux | grep -E '(apache|nginx|httpd)' | grep -v grep",
                "web_configs": "find /etc -name '*apache*' -o -name '*nginx*' 2>/dev/null | head -5",
                "web_logs": "ls -la /var/log/*access* /var/log/*error* 2>/dev/null | head -10"
            },
            
            "database_security": {
                "db_processes": "ps aux | grep -E '(mysql|postgres|mongo)' | grep -v grep",
                "db_configs": "find /etc -name 'my.cnf' -o -name 'postgresql.conf' 2>/dev/null",
                "db_logs": "ls -la /var/log/mysql* /var/log/postgresql* 2>/dev/null"
            },
            
            "network_security": {
                "open_ports": "netstat -tupln 2>/dev/null || ss -tupln 2>/dev/null",
                "firewall_status": "iptables -L -n 2>/dev/null | head -20",
                "network_services": "systemctl list-units --type=service | grep -E '(ssh|ftp|telnet|http)'"
            }
        }
        
        total_vulns_found = 0
        
        for category, checks in vuln_checks.items():
            vulnerabilities[category] = {
                "vulnerabilities_found": [],
                "evidence": {}
            }
            
            logger.info(f"🔍 Evaluando vulnerabilidades: {category}")
            FINDINGS.append(f"[VULN_CHECK] Evaluando: {category}")
            
            for check_name, command in checks.items():
                try:
                    stdout, stderr, return_code = self._execute_remote_command(
                        hostname, username, command, key_file, port, password, timeout=30
                    )
                    
                    if return_code == 0 and stdout.strip():
                        vulnerabilities[category]["evidence"][check_name] = {
                            "command": command,
                            "output": stdout.strip(),
                            "timestamp": datetime.now().isoformat()
                        }
                        
                        # Análisis básico de vulnerabilidades
                        vulns = self._analyze_vulnerability_output(check_name, stdout)
                        vulnerabilities[category]["vulnerabilities_found"].extend(vulns)
                        total_vulns_found += len(vulns)
                        
                        if vulns:
                            for vuln in vulns:
                                logger.warning(f"🚨 VULNERABILIDAD: {category} - {vuln}")
                                FINDINGS.append(f"[VULNERABILITY] {category}: {vuln}")
                        
                except Exception as e:
                    logger.error(f"💥 Error en check {check_name}: {e}")
                    FINDINGS.append(f"[VULN_ERROR] {check_name}: {str(e)}")
        
        logger.info(f"🛡️ Evaluación de vulnerabilidades completada: {total_vulns_found} vulnerabilidades encontradas")
        FINDINGS.append(f"[VULN_COMPLETE] Evaluación completada: {total_vulns_found} vulnerabilidades encontradas")
        
        # === ANÁLISIS IA DE VULNERABILIDADES AGREGADO ===
        if vulnerabilities and self.groq_available:
            logger.info("🤖 Generando análisis IA de vulnerabilidades...")
            ai_analysis = self._generate_forensic_ai_analysis(vulnerabilities, "vulnerability")
            vulnerabilities["ai_analysis"] = {
                "analysis": ai_analysis,
                "generated_at": datetime.now().isoformat(),
                "type": "vulnerability_assessment",
                "total_vulnerabilities": total_vulns_found
            }
            FINDINGS.append("[VULN_AI] ✅ Análisis IA de vulnerabilidades generado")
        
        return vulnerabilities
    
    def _analyze_vulnerability_output(self, check_name: str, output: str) -> List[str]:
        """Analiza la salida de comandos para identificar vulnerabilidades"""
        vulnerabilities = []
        output_lower = output.lower()
        
        # Análisis específico por tipo de check
        if check_name == "ssh_config_check":
            if "permitrootlogin yes" in output_lower:
                vulnerabilities.append("SSH permite login como root")
            if "passwordauthentication yes" in output_lower:
                vulnerabilities.append("SSH permite autenticación por contraseña")
            if "permitemptypasswords yes" in output_lower:
                vulnerabilities.append("SSH permite contraseñas vacías")
        
        elif check_name == "suid_binaries":
            dangerous_suid = ["find", "vim", "nano", "less", "more", "nmap"]
            for binary in dangerous_suid:
                if binary in output_lower:
                    vulnerabilities.append(f"Binario SUID peligroso encontrado: {binary}")
        
        elif check_name == "open_ports":
            dangerous_ports = ["21", "23", "135", "139", "445", "1433", "3306", "5432"]
            for port in dangerous_ports:
                if f":{port}" in output:
                    vulnerabilities.append(f"Puerto potencialmente peligroso abierto: {port}")
        
        elif check_name == "web_servers":
            if output.strip():
                vulnerabilities.append("Servidor web detectado - requiere análisis de seguridad")
        
        elif check_name == "db_processes":
            if output.strip():
                vulnerabilities.append("Base de datos detectada - verificar configuración de seguridad")
        
        return vulnerabilities
    
    def generate_comprehensive_forensic_report(self, hostname: str, username: str, 
                                             key_file: str = None, port: int = 22, 
                                             password: str = None) -> Dict:
        """
        Genera un reporte forense completo con todos los análisis + IA
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            key_file: Archivo de clave privada
            port: Puerto SSH
            password: Contraseña SSH
            
        Returns:
            Dict: Reporte forense completo
        """
        logger.info(f"📋 Generando reporte forense completo para {hostname}")
        FINDINGS.append(f"[COMPREHENSIVE_REPORT] Iniciando reporte completo de {hostname}")
        
        comprehensive_report = {
            "metadata": {
                "hostname": hostname,
                "session_id": self.session_id,
                "start_time": self.start_time.isoformat(),
                "generated_at": datetime.now().isoformat(),
                "groq_enabled": self.groq_available
            }
        }
        
        try:
            # 1. Prueba de conexión
            if not self.test_ssh_connection(hostname, username, key_file, port, password):
                comprehensive_report["error"] = "Fallo en conexión SSH"
                return comprehensive_report
            
            # 2. Escaneo rápido
            logger.info("🚀 Ejecutando escaneo rápido...")
            quick_scan_results = self.quick_scan(hostname, username, key_file, port, password)
            comprehensive_report["quick_scan"] = quick_scan_results
            
            # 3. Análisis forense completo
            logger.info("🔍 Ejecutando análisis forense completo...")
            forensic_results = self.comprehensive_system_analysis(hostname, username, key_file, port, password)
            comprehensive_report["forensic_analysis"] = forensic_results
            
            # 4. Evaluación de vulnerabilidades
            logger.info("🛡️ Ejecutando evaluación de vulnerabilidades...")
            vuln_results = self.vulnerability_assessment(hostname, username, key_file, port, password)
            comprehensive_report["vulnerability_assessment"] = vuln_results
            
            # 5. Análisis IA consolidado
            if self.groq_available:
                logger.info("🤖 Generando análisis IA consolidado...")
                consolidated_data = {
                    "quick_scan": quick_scan_results,
                    "forensic_analysis": forensic_results,
                    "vulnerabilities": vuln_results
                }
                
                consolidated_ai_analysis = self._generate_consolidated_ai_analysis(consolidated_data)
                comprehensive_report["consolidated_ai_analysis"] = {
                    "analysis": consolidated_ai_analysis,
                    "generated_at": datetime.now().isoformat(),
                    "type": "consolidated_report"
                }
                FINDINGS.append("[CONSOLIDATED_AI] ✅ Análisis IA consolidado generado")
            
            # 6. Resumen ejecutivo
            comprehensive_report["executive_summary"] = self._generate_executive_summary(comprehensive_report)
            
            # 7. Metadatos finales
            comprehensive_report["metadata"]["end_time"] = datetime.now().isoformat()
            comprehensive_report["metadata"]["total_duration"] = str(datetime.now() - self.start_time)
            comprehensive_report["metadata"]["evidence_chain_entries"] = len(self.evidence_chain)
            
            logger.info("✅ Reporte forense completo generado exitosamente")
            FINDINGS.append("[COMPREHENSIVE_COMPLETE] ✅ Reporte forense completo generado")
            
            return comprehensive_report
            
        except Exception as e:
            logger.error(f"💥 Error generando reporte completo: {e}")
            FINDINGS.append(f"[COMPREHENSIVE_ERROR] Error: {str(e)}")
            comprehensive_report["error"] = str(e)
            return comprehensive_report
    
    def _generate_consolidated_ai_analysis(self, consolidated_data: Dict) -> str:
        """Genera análisis IA consolidado de todos los datos"""
        try:
            client = Groq(api_key=os.getenv('GROQ_API_KEY'))
            
            formatted_data = self._format_consolidated_data(consolidated_data)
            
            prompt = f"""
Como experto forense digital senior, analiza todos los datos recopilados y proporciona un ANÁLISIS CONSOLIDADO:

1. RESUMEN EJECUTIVO GENERAL
2. PERFIL DEL SISTEMA OBJETIVO
3. HALLAZGOS CRÍTICOS CONSOLIDADOS
4. EVALUACIÓN DE RIESGO INTEGRAL
5. INDICADORES DE COMPROMISO (IoCs) IDENTIFICADOS
6. CRONOLOGÍA DE EVENTOS SOSPECHOSOS
7. RECOMENDACIONES ESTRATÉGICAS PRIORITARIAS
8. PLAN DE RESPUESTA A INCIDENTES

DATOS FORENSES CONSOLIDADOS:
{formatted_data}

Proporciona un análisis profesional integral que combine todos los hallazgos en un informe cohesivo y actionable en español.
"""
            
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "Eres un consultor senior en forensics digitales y respuesta a incidentes con 15+ años de experiencia. Proporciona análisis consolidados profesionales que integren todos los hallazgos en recomendaciones estratégicas."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                model="llama-3.1-70b-versatile",
                max_tokens=2500,
                temperature=0.2
            )
            
            return chat_completion.choices[0].message.content
            
        except Exception as e:
            logger.error(f"💥 Error en análisis IA consolidado: {e}")
            return f"⚠️ Error en análisis IA consolidado: {str(e)}"
    
    def _format_consolidated_data(self, data: Dict) -> str:
        """Formatea datos consolidados para análisis IA"""
        formatted = []
        
        # Escaneo rápido
        if "quick_scan" in data:
            formatted.append("\n=== ESCANEO RÁPIDO ===")
            for key, value in data["quick_scan"].items():
                if key != "ai_analysis" and isinstance(value, dict) and "output" in value:
                    formatted.append(f"{key}: {value['output'][:150]}...")
        
        # Análisis forense
        if "forensic_analysis" in data:
            formatted.append("\n=== ANÁLISIS FORENSE ===")
            for category, content in data["forensic_analysis"].items():
                if category != "ai_analysis" and isinstance(content, dict):
                    formatted.append(f"\n[{category.upper()}]")
                    for subcategory, details in content.items():
                        if isinstance(details, dict) and "output" in details:
                            formatted.append(f"{subcategory}: {details['output'][:100]}...")
        
        # Vulnerabilidades
        if "vulnerabilities" in data:
            formatted.append("\n=== VULNERABILIDADES ===")
            for category, vulns in data["vulnerabilities"].items():
                if category != "ai_analysis" and isinstance(vulns, dict):
                    if vulns.get("vulnerabilities_found"):
                        formatted.append(f"\n[{category.upper()}] - VULNERABILIDADES:")
                        for vuln in vulns["vulnerabilities_found"]:
                            formatted.append(f"- {vuln}")
        
        return "\n".join(formatted)
    
    def _generate_executive_summary(self, report: Dict) -> Dict:
        """Genera resumen ejecutivo del reporte"""
        summary = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "analysis_duration": str(datetime.now() - self.start_time),
            "components_analyzed": [],
            "total_vulnerabilities": 0,
            "risk_level": "INFORMATIVO",
            "key_findings": []
        }
        
        # Contar componentes analizados
        if "quick_scan" in report:
            summary["components_analyzed"].append("Escaneo Rápido")
        if "forensic_analysis" in report:
            summary["components_analyzed"].append("Análisis Forense")
        if "vulnerability_assessment" in report:
            summary["components_analyzed"].append("Evaluación de Vulnerabilidades")
        
        # Contar vulnerabilidades totales
        if "vulnerability_assessment" in report:
            for category, data in report["vulnerability_assessment"].items():
                if isinstance(data, dict) and "vulnerabilities_found" in data:
                    summary["total_vulnerabilities"] += len(data["vulnerabilities_found"])
        
        # Determinar nivel de riesgo
        if summary["total_vulnerabilities"] >= 10:
            summary["risk_level"] = "CRÍTICO"
        elif summary["total_vulnerabilities"] >= 5:
            summary["risk_level"] = "ALTO"
        elif summary["total_vulnerabilities"] >= 2:
            summary["risk_level"] = "MEDIO"
        elif summary["total_vulnerabilities"] >= 1:
            summary["risk_level"] = "BAJO"
        
        # Hallazgos clave básicos
        summary["key_findings"] = [
            f"Sistema analizado: {report['metadata']['hostname']}",
            f"Vulnerabilidades encontradas: {summary['total_vulnerabilities']}",
            f"Análisis IA: {'✅ Habilitado' if report['metadata']['groq_enabled'] else '❌ No disponible'}",
            f"Duración del análisis: {summary['analysis_duration']}"
        ]
        
        return summary
    
    def export_evidence_chain(self, output_file: str) -> str:
        """
        Exporta la cadena de evidencia forense
        
        Args:
            output_file: Archivo de salida
            
        Returns:
            str: Ruta del archivo exportado
        """
        try:
            evidence_data = {
                "session_id": self.session_id,
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "total_commands": len(self.evidence_chain),
                "evidence_chain": self.evidence_chain,
                "integrity_hash": hashlib.sha256(
                    json.dumps(self.evidence_chain, sort_keys=True).encode()
                ).hexdigest()
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(evidence_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"📄 Cadena de evidencia exportada: {output_file}")
            FINDINGS.append(f"[EVIDENCE_EXPORT] Cadena de evidencia exportada: {output_file}")
            
            return output_file
            
        except Exception as e:
            logger.error(f"💥 Error exportando cadena de evidencia: {e}")
            FINDINGS.append(f"[EVIDENCE_ERROR] Error exportando evidencia: {str(e)}")
            return None
