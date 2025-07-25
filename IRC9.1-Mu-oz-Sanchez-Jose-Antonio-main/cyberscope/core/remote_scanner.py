#!/usr/bin/env python3
"""
Sistema de Análisis Remoto Forense - Integrado con CyberScope
Versión: 2.0 - CORREGIDO
"""

import subprocess
import json
import datetime
import hashlib
import threading
import time
import os
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import FINDINGS, logger

@dataclass
class ForensicEvidence:
    """Estructura para evidencia forense"""
    timestamp: str
    source_host: str
    evidence_type: str
    hash_sha256: str
    command_executed: str
    raw_output: str
    analysis_metadata: Dict
    chain_of_custody: List[str]

class RemoteForensicScanner:
    """Scanner forense remoto con integridad de evidencia"""
    
    def __init__(self, config: Dict = None):
        self.config = config or self.get_default_config()
        self.evidence_chain = []
        self.session_id = self.generate_session_id()
        
        # Asegurar que las claves de configuración existen
        self._validate_config()
        
    def _validate_config(self):
        """Valida y normaliza la configuración"""
        required_keys = {
            'ssh_timeout': 30,
            'max_concurrent': 5,
            'evidence_dir': './forensic_evidence',
            'hash_algorithm': 'sha256',
            'preserve_artifacts': True,
            'chain_of_custody': True
        }
        
        # Mapear claves de configuración alternativas
        key_mapping = {
            'timeout': 'ssh_timeout',
            'ssh.timeout': 'ssh_timeout',
            'analysis.max_concurrent_hosts': 'max_concurrent'
        }
        
        # Aplicar mapeo
        for old_key, new_key in key_mapping.items():
            if old_key in self.config and new_key not in self.config:
                self.config[new_key] = self.config[old_key]
        
        # Asegurar que existen todas las claves requeridas
        for key, default_value in required_keys.items():
            if key not in self.config:
                self.config[key] = default_value
                logger.info(f"Configuración: {key} establecido a valor por defecto: {default_value}")
        
        # Validar configuración anidada de SSH
        if 'ssh' in self.config:
            ssh_config = self.config['ssh']
            if 'timeout' in ssh_config:
                self.config['ssh_timeout'] = ssh_config['timeout']
        
        logger.debug(f"Configuración validada: {self.config}")
        
    def get_default_config(self) -> Dict:
        """Configuración por defecto"""
        return {
            "ssh_timeout": 30,
            "max_concurrent": 5,
            "evidence_dir": "./forensic_evidence",
            "hash_algorithm": "sha256",
            "preserve_artifacts": True,
            "chain_of_custody": True
        }
    
    def generate_session_id(self) -> str:
        """Genera ID único de sesión forense"""
        timestamp = datetime.datetime.now().isoformat()
        return hashlib.sha256(timestamp.encode()).hexdigest()[:16]
    
    def calculate_evidence_hash(self, data: str) -> str:
        """Calcula hash de integridad para evidencia"""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def execute_remote_command(self, host: str, user: str, command: str, 
                             key_file: Optional[str] = None, port: int = 22) -> Tuple[str, str, int, str]:
        """Ejecuta comando remoto con logging forense"""
        # Validar parámetros de entrada
        if not host or not user:
            error_msg = "Host y usuario son requeridos"
            FINDINGS.append(f"[SSH_ERROR] {error_msg}")
            return "", error_msg, 1, f"VALIDATION_ERROR|{error_msg}"
        
        if not command or not command.strip():
            error_msg = "Comando no puede estar vacío"
            FINDINGS.append(f"[SSH_ERROR] {error_msg}")
            return "", error_msg, 1, f"VALIDATION_ERROR|{error_msg}"
        
        ssh_cmd = self.build_ssh_command(host, user, command, key_file, port)
        
        start_time = datetime.datetime.now()
        logger.info(f"Ejecutando comando forense en {host}: {command[:100]}...")
        FINDINGS.append(f"[SSH_EXEC] {host}: {command[:100]}...")
        
        try:
            # Usar timeout de configuración validada
            timeout_value = self.config.get('ssh_timeout', 30)
            
            result = subprocess.run(
                ssh_cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout_value
            )
            
            execution_time = (datetime.datetime.now() - start_time).total_seconds()
            
            # Registrar en cadena de custodia
            custody_entry = f"CMD_EXEC|{host}|{user}|{start_time.isoformat()}|{execution_time}s"
            
            if result.returncode == 0:
                FINDINGS.append(f"[SSH_SUCCESS] {host}: Comando ejecutado exitosamente")
                logger.debug(f"Comando exitoso en {host}, salida: {len(result.stdout)} caracteres")
            else:
                FINDINGS.append(f"[SSH_ERROR] {host}: Error en comando (código: {result.returncode})")
                logger.warning(f"Comando falló en {host} con código {result.returncode}: {result.stderr[:200]}")
            
            return result.stdout, result.stderr, result.returncode, custody_entry
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout en comando remoto: {host} (timeout: {timeout_value}s)")
            FINDINGS.append(f"[SSH_TIMEOUT] {host}: Timeout en comando SSH ({timeout_value}s)")
            return "", f"TIMEOUT_ERROR after {timeout_value}s", 124, f"TIMEOUT|{host}|{command[:50]}"
        except Exception as e:
            logger.error(f"Error ejecutando comando en {host}: {str(e)}")
            FINDINGS.append(f"[SSH_ERROR] {host}: {str(e)}")
            return "", str(e), 1, f"ERROR|{host}|{str(e)}"
    
    def build_ssh_command(self, host: str, user: str, command: str, 
                         key_file: Optional[str] = None, port: int = 22) -> str:
        """Construye comando SSH seguro"""
        # Validar parámetros
        if not host or not user or not command:
            raise ValueError("Host, usuario y comando son requeridos")
        
        # Sanitizar comando para evitar inyección
        if any(char in command for char in [';', '&&', '||', '`', '$(']):
            logger.warning(f"Comando contiene caracteres potencialmente peligrosos: {command[:50]}...")
        
        timeout_value = self.config.get('ssh_timeout', 30)
        
        ssh_options = [
            "-o StrictHostKeyChecking=no",
            "-o UserKnownHostsFile=/dev/null",
            "-o LogLevel=ERROR",
            "-o BatchMode=yes",  # No solicitar contraseñas interactivamente
            "-o ConnectTimeout=10",  # Timeout de conexión más corto
            "-o ServerAliveInterval=5",  # Keep-alive
            "-o ServerAliveCountMax=3",
            f"-p {port}"
        ]
        
        if key_file and key_file.strip():
            # Validar que el archivo de clave existe
            if os.path.exists(key_file):
                ssh_options.append(f"-i {key_file}")
            else:
                logger.warning(f"Archivo de clave SSH no encontrado: {key_file}")
                FINDINGS.append(f"[SSH_WARNING] Archivo de clave no encontrado: {key_file}")
            
        # Escapar comando para shell
        escaped_command = command.replace("'", "'\"'\"'")
        ssh_cmd = f"ssh {' '.join(ssh_options)} {user}@{host} '{escaped_command}'"
        
        logger.debug(f"Comando SSH construido: {ssh_cmd[:100]}...")
        return ssh_cmd
    
    def comprehensive_system_analysis(self, host: str, user: str, 
                                   key_file: Optional[str] = None, port: int = 22) -> Dict:
        """Análisis integral del sistema con evidencia forense"""
        
        # Validar parámetros de entrada
        if not host or not user:
            error_msg = "Host y usuario son requeridos para el análisis"
            FINDINGS.append(f"[REMOTE_ERROR] {error_msg}")
            logger.error(error_msg)
            return {}
        
        FINDINGS.append(f"[REMOTE_SCAN] Iniciando análisis forense remoto de {host}")
        logger.info(f"Iniciando análisis comprehensivo de {host}")
        
        forensic_commands = {
            "system_identification": {
                "command": """
                    echo "=== SYSTEM_ID ===";
                    hostname 2>/dev/null;
                    uname -a 2>/dev/null;
                    cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || cat /etc/issue 2>/dev/null;
                    uptime 2>/dev/null;
                    date 2>/dev/null;
                    timedatectl status 2>/dev/null || echo "timedatectl no disponible";
                """,
                "priority": 1,
                "description": "Identificación básica del sistema"
            },
            
            "user_activity_forensics": {
                "command": """
                    echo "=== USER_FORENSICS ===";
                    whoami 2>/dev/null;
                    id 2>/dev/null;
                    last -n 20 2>/dev/null || echo "last no disponible";
                    lastlog 2>/dev/null | head -20 || echo "lastlog no disponible";
                    w 2>/dev/null || echo "w no disponible";
                    who -a 2>/dev/null || who 2>/dev/null || echo "who no disponible";
                    users 2>/dev/null || echo "users no disponible";
                    cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v false || echo "passwd no accesible";
                    sudo -l 2>/dev/null || echo "sudo no disponible";
                """,
                "priority": 2,
                "description": "Análisis forense de actividad de usuarios"
            },
            
            "process_memory_analysis": {
                "command": """
                    echo "=== PROCESS_ANALYSIS ===";
                    ps auxf 2>/dev/null || ps aux 2>/dev/null || echo "ps no disponible";
                    ps -eo pid,ppid,user,cmd,lstart,etime --sort=-start_time 2>/dev/null || echo "ps extendido no disponible";
                    pstree -p 2>/dev/null || echo "pstree no disponible";
                    lsof -i 2>/dev/null | head -50 || netstat -tupln 2>/dev/null | head -50 || echo "lsof/netstat no disponibles";
                """,
                "priority": 1,
                "description": "Análisis de procesos y memoria"
            },
            
            "network_forensics": {
                "command": """
                    echo "=== NETWORK_FORENSICS ===";
                    ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Configuración de red no disponible";
                    ip route show 2>/dev/null || route -n 2>/dev/null || echo "Tabla de rutas no disponible";
                    arp -a 2>/dev/null || echo "ARP no disponible";
                    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo "netstat/ss no disponibles";
                    netstat -tupln 2>/dev/null || ss -tupln 2>/dev/null || echo "conexiones activas no disponibles";
                    iptables -L -n 2>/dev/null || echo "iptables no accesible";
                """,
                "priority": 1,
                "description": "Análisis forense de red"
            },
            
            "service_security_analysis": {
                "command": """
                    echo "=== SERVICE_SECURITY ===";
                    systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null || echo "servicios no disponibles";
                    systemctl list-unit-files --type=service --state=enabled 2>/dev/null || echo "servicios habilitados no disponibles";
                    chkconfig --list 2>/dev/null || echo "chkconfig no disponible";
                    crontab -l 2>/dev/null || echo "crontab usuario vacío";
                    cat /etc/crontab 2>/dev/null || echo "crontab sistema no accesible";
                    ls -la /etc/cron* 2>/dev/null || echo "directorios cron no accesibles";
                """,
                "priority": 2,
                "description": "Análisis de seguridad de servicios"
            },
            
            "file_system_forensics": {
                "command": """
                    echo "=== FILESYSTEM_FORENSICS ===";
                    df -h 2>/dev/null || echo "df no disponible";
                    mount 2>/dev/null || echo "mount no disponible";
                    lsblk 2>/dev/null || echo "lsblk no disponible";
                    find /tmp -type f -mtime -1 2>/dev/null | head -20 || echo "tmp no accesible";
                    find /var/tmp -type f -mtime -1 2>/dev/null | head -20 || echo "var/tmp no accesible";
                    find / -perm -4000 -type f 2>/dev/null | head -30 || echo "SUID no accesible";
                    find / -perm -2000 -type f 2>/dev/null | head -30 || echo "SGID no accesible";
                """,
                "priority": 2,
                "description": "Análisis forense del sistema de archivos"
            },
            
            "security_configuration": {
                "command": """
                    echo "=== SECURITY_CONFIG ===";
                    cat /etc/ssh/sshd_config 2>/dev/null | grep -E '^[^#]' || echo "sshd_config no accesible";
                    cat /etc/sudoers 2>/dev/null | grep -E '^[^#]' || echo "sudoers no accesible";
                    cat /etc/hosts.allow 2>/dev/null || echo "hosts.allow no encontrado";
                    cat /etc/hosts.deny 2>/dev/null || echo "hosts.deny no encontrado";
                    sestatus 2>/dev/null || echo "SELinux no disponible";
                    getenforce 2>/dev/null || echo "getenforce no disponible";
                    ufw status 2>/dev/null || echo "UFW no disponible";
                """,
                "priority": 2,
                "description": "Análisis de configuración de seguridad"
            },
            
            "log_analysis": {
                "command": """
                    echo "=== LOG_ANALYSIS ===";
                    tail -50 /var/log/auth.log 2>/dev/null || tail -50 /var/log/secure 2>/dev/null || echo "logs de auth no accesibles";
                    tail -50 /var/log/syslog 2>/dev/null || tail -50 /var/log/messages 2>/dev/null || echo "syslog no accesible";
                    grep -i "failed\\|error\\|warning" /var/log/auth.log 2>/dev/null | tail -20 || echo "búsqueda en auth.log falló";
                    grep -i "sudo" /var/log/auth.log 2>/dev/null | tail -10 || echo "búsqueda sudo falló";
                    dmesg 2>/dev/null | tail -30 || echo "dmesg no disponible";
                """,
                "priority": 3,
                "description": "Análisis de logs del sistema"
            },
            
            "application_analysis": {
                "command": """
                    echo "=== APPLICATION_ANALYSIS ===";
                    dpkg -l 2>/dev/null | grep -E '(apache|nginx|mysql|php|ssh|ftp)' || rpm -qa 2>/dev/null | grep -E '(apache|nginx|mysql|php|ssh|ftp)' || echo "listado de paquetes no disponible";
                    apache2 -v 2>/dev/null || httpd -v 2>/dev/null || echo "Apache no instalado";
                    nginx -v 2>/dev/null || echo "Nginx no instalado";
                    mysql --version 2>/dev/null || echo "MySQL no instalado";
                    php --version 2>/dev/null || echo "PHP no instalado";
                    python --version 2>/dev/null || echo "Python2 no instalado";
                    python3 --version 2>/dev/null || echo "Python3 no instalado";
                    java -version 2>&1 || echo "Java no instalado";
                """,
                "priority": 3,
                "description": "Análisis de aplicaciones instaladas"
            }
        }
        
        evidence_collection = {}
        successful_commands = 0
        failed_commands = 0
        
        # Ejecutar comandos por prioridad
        for category, cmd_info in sorted(forensic_commands.items(), 
                                       key=lambda x: x[1]["priority"]):
            
            logger.info(f"Recopilando evidencia: {category} - {cmd_info['description']}")
            FINDINGS.append(f"[REMOTE_EVIDENCE] {host}: Recopilando {category}")
            
            stdout, stderr, returncode, custody = self.execute_remote_command(
                host, user, cmd_info["command"], key_file, port
            )
            
            if returncode == 0 and stdout:
                successful_commands += 1
                # Crear evidencia forense
                evidence = ForensicEvidence(
                    timestamp=datetime.datetime.now().isoformat(),
                    source_host=host,
                    evidence_type=category,
                    hash_sha256=self.calculate_evidence_hash(stdout + stderr),
                    command_executed=cmd_info["command"],
                    raw_output=stdout,
                    analysis_metadata={
                        "stderr": stderr,
                        "return_code": returncode,
                        "execution_priority": cmd_info["priority"],
                        "description": cmd_info["description"]
                    },
                    chain_of_custody=[custody, f"PROCESSED|{self.session_id}"]
                )
                
                evidence_collection[category] = evidence
                self.evidence_chain.append(evidence)
                
                # Agregar hallazgos específicos
                self.analyze_evidence_for_findings(category, stdout, host)
                
            else:
                failed_commands += 1
                logger.warning(f"Falló comando {category} en {host}: {stderr}")
                FINDINGS.append(f"[REMOTE_ERROR] {host}: Falló {category} - {stderr[:100]}")
        
        FINDINGS.append(f"[REMOTE_SCAN] Análisis forense completado para {host} - Éxito: {successful_commands}, Fallos: {failed_commands}")
        logger.info(f"Análisis completado para {host}: {successful_commands} exitosos, {failed_commands} fallidos")
        
        return evidence_collection
    
    def analyze_evidence_for_findings(self, category: str, output: str, host: str):
        """Analiza evidencia y genera hallazgos específicos"""
        
        if not output or not output.strip():
            return
            
        try:
            if category == "user_activity_forensics":
                self.analyze_user_activity(output, host)
            elif category == "network_forensics":
                self.analyze_network_security(output, host)
            elif category == "service_security_analysis":
                self.analyze_services(output, host)
            elif category == "file_system_forensics":
                self.analyze_filesystem(output, host)
            elif category == "security_configuration":
                self.analyze_security_config(output, host)
            elif category == "log_analysis":
                self.analyze_logs(output, host)
            elif category == "process_memory_analysis":
                self.analyze_processes(output, host)
            elif category == "system_identification":
                self.analyze_system_info(output, host)
                
        except Exception as e:
            logger.error(f"Error analizando evidencia {category} para {host}: {e}")
            FINDINGS.append(f"[REMOTE_ANALYSIS_ERROR] {host}: Error en análisis {category}")
    
    def analyze_system_info(self, output: str, host: str):
        """Analiza información básica del sistema"""
        if "Ubuntu" in output:
            FINDINGS.append(f"[REMOTE_OS] {host}: Sistema Ubuntu detectado")
        elif "CentOS" in output or "Red Hat" in output:
            FINDINGS.append(f"[REMOTE_OS] {host}: Sistema Red Hat/CentOS detectado")
        elif "Debian" in output:
            FINDINGS.append(f"[REMOTE_OS] {host}: Sistema Debian detectado")
            
        # Buscar tiempo de actividad
        if "up" in output and "day" in output:
            FINDINGS.append(f"[REMOTE_UPTIME] {host}: Sistema con alta disponibilidad detectado")
    
    def analyze_user_activity(self, output: str, host: str):
        """Analiza actividad de usuarios"""
        
        if "root" in output and "pts/" in output:
            FINDINGS.append(f"[REMOTE_FINDING] {host}: Actividad de login como root detectada")
        
        if "NOPASSWD" in output:
            FINDINGS.append(f"[REMOTE_FINDING] {host}: Usuario configurado con sudo sin contraseña")
        
        # Buscar usuarios sospechosos
        lines = output.split('\n')
        bash_users = []
        for line in lines:
            if '/bin/bash' in line and 'root' not in line and ':' in line:
                try:
                    user = line.split(':')[0]
                    if user and user not in bash_users:
                        bash_users.append(user)
                        FINDINGS.append(f"[REMOTE_USER] {host}: Usuario con shell bash: {user}")
                except IndexError:
                    continue
        
        # Analizar intentos de login recientes
        if "Failed password" in output:
            failed_count = output.count("Failed password")
            FINDINGS.append(f"[REMOTE_AUTH] {host}: {failed_count} intentos de login fallidos recientes")
    
    def analyze_network_security(self, output: str, host: str):
        """Analiza seguridad de red"""
        
        # Puertos peligrosos abiertos
        dangerous_ports = ["23", "135", "445", "1433", "3389", "5900", "21"]
        open_dangerous_ports = []
        
        for port in dangerous_ports:
            if f":{port}" in output or f" {port} " in output:
                open_dangerous_ports.append(port)
                FINDINGS.append(f"[REMOTE_VULN] {host}: Puerto peligroso {port} abierto")
        
        # Buscar conexiones sospechosas
        if "ESTABLISHED" in output:
            lines = output.split('\n')
            for line in lines:
                if "ESTABLISHED" in line:
                    for port in dangerous_ports:
                        if port in line:
                            FINDINGS.append(f"[REMOTE_CONNECTION] {host}: Conexión activa sospechosa en puerto {port}")
                            break
        
        # Detectar interfaces de red
        if "eth0" in output or "ens" in output or "enp" in output:
            FINDINGS.append(f"[REMOTE_NETWORK] {host}: Interfaces de red detectadas")
    
    def analyze_services(self, output: str, host: str):
        """Analiza servicios en ejecución"""
        
        suspicious_services = ["telnet", "rsh", "rlogin", "ftp"]
        for service in suspicious_services:
            if service in output.lower():
                FINDINGS.append(f"[REMOTE_SERVICE] {host}: Servicio inseguro detectado: {service}")
        
        # Buscar servicios web
        web_services = ["apache", "nginx", "httpd"]
        for service in web_services:
            if service in output.lower():
                FINDINGS.append(f"[REMOTE_WEB] {host}: Servidor web detectado ({service})")
        
        # Buscar bases de datos
        db_services = ["mysql", "postgres", "mongodb", "mariadb"]
        for service in db_services:
            if service in output.lower():
                FINDINGS.append(f"[REMOTE_DB] {host}: Servidor de base de datos detectado ({service})")
        
        # Buscar servicios SSH
        if "ssh" in output.lower() or "sshd" in output.lower():
            FINDINGS.append(f"[REMOTE_SSH_SERVICE] {host}: Servicio SSH activo")
    
    def analyze_filesystem(self, output: str, host: str):
        """Analiza sistema de archivos"""
        
        # Buscar archivos SUID peligrosos
        dangerous_suid = ["nmap", "vim", "find", "bash", "more", "less", "nano", "awk", "python"]
        for binary in dangerous_suid:
            if binary in output:
                FINDINGS.append(f"[REMOTE_SUID] {host}: Binario SUID peligroso encontrado: {binary}")
        
        # Buscar archivos temporales recientes
        temp_file_count = 0
        lines = output.split('\n')
        for line in lines:
            if '/tmp/' in line or '/var/tmp/' in line:
                temp_file_count += 1
        
        if temp_file_count > 0:
            FINDINGS.append(f"[REMOTE_TEMP] {host}: {temp_file_count} archivos temporales recientes encontrados")
        
        # Analizar uso de disco
        if "%" in output and ("100%" in output or "9[0-9]%" in output):
            FINDINGS.append(f"[REMOTE_DISK] {host}: Partición con poco espacio libre detectada")
    
    def analyze_security_config(self, output: str, host: str):
        """Analiza configuración de seguridad"""
        
        # SSH Configuration
        if "PermitRootLogin yes" in output:
            FINDINGS.append(f"[REMOTE_SSH] {host}: Login root por SSH habilitado (riesgo)")
        
        if "PasswordAuthentication yes" in output:
            FINDINGS.append(f"[REMOTE_SSH] {host}: Autenticación por contraseña habilitada")
        
        if "Protocol 1" in output:
            FINDINGS.append(f"[REMOTE_SSH] {host}: Protocolo SSH v1 habilitado (CRÍTICO)")
        
        if "Port 22" in output or "#Port 22" in output:
            FINDINGS.append(f"[REMOTE_SSH] {host}: SSH en puerto estándar 22")
        
        # Firewall status
        if "inactive" in output.lower() or "disabled" in output.lower():
            FINDINGS.append(f"[REMOTE_FIREWALL] {host}: Firewall deshabilitado")
        
        # SELinux status
        if "Enforcing" in output:
            FINDINGS.append(f"[REMOTE_SELINUX] {host}: SELinux en modo Enforcing (buena práctica)")
        elif "Permissive" in output or "Disabled" in output:
            FINDINGS.append(f"[REMOTE_SELINUX] {host}: SELinux deshabilitado o permisivo")
    
    def analyze_logs(self, output: str, host: str):
        """Analiza logs del sistema"""
        
        # Buscar intentos de login fallidos
        failed_logins = output.count("Failed password") + output.count("authentication failure")
        if failed_logins > 0:
            FINDINGS.append(f"[REMOTE_AUTH] {host}: {failed_logins} intentos de autenticación fallidos")
        
        # Buscar uso de sudo
        sudo_usage = output.count("sudo:") + output.count("COMMAND=")
        if sudo_usage > 0:
            FINDINGS.append(f"[REMOTE_SUDO] {host}: {sudo_usage} ejecuciones de sudo detectadas")
        
        # Buscar errores críticos
        critical_errors = output.count("CRITICAL") + output.count("FATAL")
        if critical_errors > 0:
            FINDINGS.append(f"[REMOTE_CRITICAL] {host}: {critical_errors} errores críticos en logs")
        
        # Buscar errores del sistema
        system_errors = output.lower().count("error") + output.lower().count("warning")
        if system_errors > 10:  # Solo reportar si hay muchos errores
            FINDINGS.append(f"[REMOTE_ERROR] {host}: {system_errors} errores/advertencias en logs")
    
    def analyze_processes(self, output: str, host: str):
        """Analiza procesos en ejecución"""
        
        # Buscar procesos sospechosos
        suspicious_processes = ["nc", "netcat", "ncat", "socat", "python -c", "perl -e", "bash -i", "/bin/sh"]
        for process in suspicious_processes:
            if process in output.lower():
                FINDINGS.append(f"[REMOTE_PROCESS] {host}: Proceso potencialmente sospechoso: {process}")
        
        # Buscar procesos con alta CPU (análisis básico)
        lines = output.split('\n')
        high_cpu_processes = 0
        for line in lines:
            if '%CPU' not in line and len(line.split()) > 2:
                try:
                    # Intentar extraer uso de CPU (formato puede variar)
                    parts = line.split()
                    if len(parts) > 2:
                        cpu_field = parts[2]
                        if cpu_field.replace('.', '').isdigit():
                            cpu_usage = float(cpu_field)
                            if cpu_usage > 80.0:
                                high_cpu_processes += 1
                                if high_cpu_processes <= 3:  # Limitar output
                                    process_name = ' '.join(parts[10:])[:50] if len(parts) > 10 else 'proceso desconocido'
                                    FINDINGS.append(f"[REMOTE_CPU] {host}: Proceso con alta CPU ({cpu_usage}%): {process_name}")
                except (ValueError, IndexError):
                    continue
        
        if high_cpu_processes > 3:
            FINDINGS.append(f"[REMOTE_CPU] {host}: {high_cpu_processes} procesos con alta CPU detectados")
    
    def vulnerability_assessment(self, host: str, user: str, 
                               key_file: Optional[str] = None, port: int = 22) -> Dict:
        """Evaluación de vulnerabilidades específica"""
        
        FINDINGS.append(f"[REMOTE_VULN] Iniciando evaluación de vulnerabilidades en {host}")
        logger.info(f"Iniciando evaluación de vulnerabilidades para {host}")
        
        vuln_checks = {
            "ssh_security": {
                "command": """
                    echo "=== SSH_VULNS ===";
                    ssh -V 2>&1 || echo "SSH version no disponible";
                    cat /etc/ssh/sshd_config 2>/dev/null | grep -E '(PermitRootLogin|PasswordAuthentication|Protocol|Ciphers|Port)' | grep -v '^#' || echo "sshd_config no accesible";
                    netstat -tulpn 2>/dev/null | grep :22 || ss -tulpn 2>/dev/null | grep :22 || echo "puerto SSH no detectado";
                """,
                "description": "Análisis de seguridad SSH"
            },
            
            "web_vulnerabilities": {
                "command": """
                    echo "=== WEB_VULNS ===";
                    find /var/www /var/html /srv/www -name "*.php" 2>/dev/null | head -5 || echo "archivos PHP no encontrados";
                    find /var/www /var/html /srv/www -name ".git" -type d 2>/dev/null || echo "directorios .git no encontrados";
                    find /var/www /var/html /srv/www -name "config.php" -o -name ".env" 2>/dev/null | head -5 || echo "archivos de config no encontrados";
                    ls -la /var/www/html/.git/config 2>/dev/null || echo "git config no accesible";
                    ps aux 2>/dev/null | grep -E "(apache|nginx|httpd)" | grep -v grep || echo "servidores web no detectados";
                """,
                "description": "Análisis de vulnerabilidades web"
            },
            
            "privilege_escalation": {
                "command": """
                    echo "=== PRIVESC_VULNS ===";
                    find / -perm -4000 2>/dev/null | grep -E "(nmap|vim|find|bash|more|less|nano|python|perl)" | head -10 || echo "binarios SUID peligrosos no encontrados";
                    sudo -l 2>/dev/null || echo "sudo no disponible o sin permisos";
                    cat /etc/sudoers 2>/dev/null | grep NOPASSWD || echo "sudoers NOPASSWD no encontrado";
                    find /etc -writable -type f 2>/dev/null | head -10 || echo "archivos /etc escribibles no encontrados";
                    ls -la /etc/passwd /etc/shadow 2>/dev/null || echo "archivos de usuarios no accesibles";
                """,
                "description": "Análisis de escalación de privilegios"
            },
            
            "database_security": {
                "command": """
                    echo "=== DB_VULNS ===";
                    mysql -e "SELECT version();" 2>/dev/null || echo "MySQL no accesible";
                    psql -c "SELECT version();" 2>/dev/null || echo "PostgreSQL no accesible";
                    find /var/lib/mysql /var/lib/postgresql -name "*.sql" -type f 2>/dev/null | head -5 || echo "archivos SQL no encontrados";
                    netstat -tulpn 2>/dev/null | grep -E "(3306|5432|27017)" || ss -tulpn 2>/dev/null | grep -E "(3306|5432|27017)" || echo "puertos DB no detectados";
                    ps aux 2>/dev/null | grep -E "(mysql|postgres|mongo)" | grep -v grep || echo "procesos DB no detectados";
                """,
                "description": "Análisis de seguridad de bases de datos"
            },
            
            "network_security": {
                "command": """
                    echo "=== NETWORK_VULNS ===";
                    netstat -tulpn 2>/dev/null | grep -E "(21|23|135|445|1433|3389|5900)" || ss -tulpn 2>/dev/null | grep -E "(21|23|135|445|1433|3389|5900)" || echo "puertos peligrosos no detectados";
                    iptables -L -n 2>/dev/null | grep -E "(ACCEPT|DROP|REJECT)" | head -10 || echo "reglas iptables no accesibles";
                    cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null || echo "archivos hosts.allow/deny no encontrados";
                    netstat -i 2>/dev/null || ip link show 2>/dev/null || echo "interfaces de red no accesibles";
                """,
                "description": "Análisis de seguridad de red"
            }
        }
        
        vulnerability_evidence = {}
        successful_checks = 0
        
        for vuln_type, check_info in vuln_checks.items():
            logger.info(f"Ejecutando verificación de vulnerabilidades: {vuln_type}")
            FINDINGS.append(f"[REMOTE_VULN_CHECK] {host}: Verificando {vuln_type}")
            
            stdout, stderr, returncode, custody = self.execute_remote_command(
                host, user, check_info["command"], key_file, port
            )
            
            if stdout:  # Si hay salida, analizar
                successful_checks += 1
                # Analizar salida para vulnerabilidades
                vuln_analysis = self.analyze_vulnerability_output(vuln_type, stdout, host)
                
                vulnerability_evidence[vuln_type] = {
                    "raw_output": stdout,
                    "vulnerabilities_found": vuln_analysis,
                    "evidence_hash": self.calculate_evidence_hash(stdout),
                    "custody": custody,
                    "description": check_info["description"],
                    "timestamp": datetime.datetime.now().isoformat()
                }
            else:
                logger.warning(f"No se obtuvo salida para {vuln_type} en {host}")
                vulnerability_evidence[vuln_type] = {
                    "raw_output": "",
                    "vulnerabilities_found": [],
                    "evidence_hash": "",
                    "custody": custody,
                    "description": check_info["description"],
                    "error": stderr or "Sin salida",
                    "timestamp": datetime.datetime.now().isoformat()
                }
        
        FINDINGS.append(f"[REMOTE_VULN] Evaluación completada para {host} - {successful_checks}/{len(vuln_checks)} verificaciones exitosas")
        logger.info(f"Evaluación de vulnerabilidades completada para {host}: {successful_checks} exitosas")
        
        return vulnerability_evidence
    
    def analyze_vulnerability_output(self, vuln_type: str, output: str, host: str) -> List[str]:
        """Analiza salida para identificar vulnerabilidades específicas"""
        vulnerabilities = []
        
        try:
            if vuln_type == "ssh_security":
                if "PermitRootLogin yes" in output:
                    vulnerabilities.append("ROOT_LOGIN_ENABLED")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: SSH - Login root habilitado (ALTO RIESGO)")
                
                if "PasswordAuthentication yes" in output:
                    vulnerabilities.append("PASSWORD_AUTH_ENABLED")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: SSH - Autenticación por contraseña habilitada")
                
                if "Protocol 1" in output:
                    vulnerabilities.append("SSH_PROTOCOL_1_ENABLED")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: SSH - Protocolo v1 habilitado (CRÍTICO)")
                
                if "Port 22" in output or not any("Port " in line for line in output.split('\n')):
                    vulnerabilities.append("SSH_DEFAULT_PORT")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: SSH - Puerto por defecto 22 en uso")
                
                # Verificar versión SSH antigua
                if "OpenSSH" in output:
                    import re
                    version_match = re.search(r'OpenSSH_(\d+)\.(\d+)', output)
                    if version_match:
                        major, minor = int(version_match.group(1)), int(version_match.group(2))
                        if major < 7 or (major == 7 and minor < 4):
                            vulnerabilities.append("SSH_OUTDATED_VERSION")
                            FINDINGS.append(f"[REMOTE_VULN] {host}: SSH - Versión desactualizada detectada")
                    
            elif vuln_type == "web_vulnerabilities":
                if ".php" in output and "/var/www" in output:
                    vulnerabilities.append("PHP_FILES_FOUND")
                    FINDINGS.append(f"[REMOTE_WEB] {host}: Archivos PHP detectados en servidor web")
                
                if ".git" in output:
                    vulnerabilities.append("GIT_DIRECTORY_EXPOSED")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: Web - Directorio .git expuesto (ALTO RIESGO)")
                
                if "config.php" in output or ".env" in output:
                    vulnerabilities.append("CONFIG_FILES_EXPOSED")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: Web - Archivos de configuración detectados")
                
                if "apache" in output.lower() or "nginx" in output.lower() or "httpd" in output.lower():
                    vulnerabilities.append("WEB_SERVER_DETECTED")
                    FINDINGS.append(f"[REMOTE_WEB] {host}: Servidor web activo detectado")
                    
            elif vuln_type == "privilege_escalation":
                dangerous_suid = ["nmap", "vim", "find", "bash", "more", "less", "python", "perl"]
                found_suid = []
                
                for binary in dangerous_suid:
                    if binary in output:
                        found_suid.append(binary)
                        vulnerabilities.append(f"SUID_{binary.upper()}_FOUND")
                        FINDINGS.append(f"[REMOTE_VULN] {host}: PrivEsc - SUID {binary} encontrado (ALTO RIESGO)")
                
                if "NOPASSWD" in output:
                    vulnerabilities.append("SUDO_NOPASSWD_CONFIGURED")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: PrivEsc - Sudo sin contraseña configurado (ALTO RIESGO)")
                
                if "/etc" in output and "writable" in output:
                    vulnerabilities.append("ETC_WRITABLE_FILES")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: PrivEsc - Archivos escribibles en /etc")
                
                if found_suid:
                    FINDINGS.append(f"[REMOTE_SUMMARY] {host}: {len(found_suid)} binarios SUID peligrosos encontrados")
            
            elif vuln_type == "database_security":
                db_ports_found = []
                
                if "3306" in output:  # MySQL
                    vulnerabilities.append("MYSQL_PORT_EXPOSED")
                    db_ports_found.append("MySQL (3306)")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: DB - Puerto MySQL 3306 expuesto")
                
                if "5432" in output:  # PostgreSQL
                    vulnerabilities.append("POSTGRESQL_PORT_EXPOSED")
                    db_ports_found.append("PostgreSQL (5432)")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: DB - Puerto PostgreSQL 5432 expuesto")
                
                if "27017" in output:  # MongoDB
                    vulnerabilities.append("MONGODB_PORT_EXPOSED")
                    db_ports_found.append("MongoDB (27017)")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: DB - Puerto MongoDB 27017 expuesto")
                
                if "mysql" in output.lower() and "process" in output.lower():
                    vulnerabilities.append("MYSQL_PROCESS_RUNNING")
                    FINDINGS.append(f"[REMOTE_DB] {host}: Proceso MySQL activo detectado")
                
                if "postgres" in output.lower() and "process" in output.lower():
                    vulnerabilities.append("POSTGRESQL_PROCESS_RUNNING")
                    FINDINGS.append(f"[REMOTE_DB] {host}: Proceso PostgreSQL activo detectado")
                
                if db_ports_found:
                    FINDINGS.append(f"[REMOTE_SUMMARY] {host}: Bases de datos expuestas: {', '.join(db_ports_found)}")
            
            elif vuln_type == "network_security":
                dangerous_ports = {
                    "21": "FTP",
                    "23": "Telnet", 
                    "135": "RPC",
                    "445": "SMB",
                    "1433": "MSSQL",
                    "3389": "RDP",
                    "5900": "VNC"
                }
                
                exposed_ports = []
                for port, service in dangerous_ports.items():
                    if port in output:
                        vulnerabilities.append(f"DANGEROUS_PORT_{port}_OPEN")
                        exposed_ports.append(f"{service} ({port})")
                        FINDINGS.append(f"[REMOTE_VULN] {host}: Red - Puerto peligroso {port} ({service}) abierto")
                
                if "ACCEPT" in output and "iptables" not in output.lower():
                    vulnerabilities.append("FIREWALL_PERMISSIVE")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: Red - Configuración de firewall permisiva")
                
                if exposed_ports:
                    FINDINGS.append(f"[REMOTE_SUMMARY] {host}: Puertos peligrosos expuestos: {', '.join(exposed_ports)}")
                
        except Exception as e:
            logger.error(f"Error analizando vulnerabilidades {vuln_type} para {host}: {e}")
            FINDINGS.append(f"[REMOTE_ANALYSIS_ERROR] {host}: Error analizando {vuln_type}")
        
        return vulnerabilities
    
    def test_ssh_connection(self, host: str, user: str, 
                          key_file: Optional[str] = None, port: int = 22) -> bool:
        """Prueba la conexión SSH antes del análisis"""
        
        logger.info(f"Probando conexión SSH a {host}:{port} como {user}")
        FINDINGS.append(f"[SSH_TEST] Probando conexión a {host}:{port}")
        
        test_command = "echo 'SSH_CONNECTION_TEST_OK' && whoami && hostname"
        stdout, stderr, returncode, _ = self.execute_remote_command(
            host, user, test_command, key_file, port
        )
        
        if returncode == 0 and "SSH_CONNECTION_TEST_OK" in stdout:
            # Extraer información adicional de la conexión exitosa
            lines = stdout.strip().split('\n')
            if len(lines) >= 3:
                remote_user = lines[1].strip()
                remote_hostname = lines[2].strip()
                
                FINDINGS.append(f"[SSH_TEST] {host}: Conexión SSH exitosa - Usuario: {remote_user}, Hostname: {remote_hostname}")
                logger.info(f"Conexión SSH exitosa a {host} - Usuario remoto: {remote_user}, Hostname: {remote_hostname}")
            else:
                FINDINGS.append(f"[SSH_TEST] {host}: Conexión SSH exitosa")
                logger.info(f"Conexión SSH exitosa a {host}")
            
            return True
        else:
            error_detail = stderr[:200] if stderr else "Sin detalles de error"
            FINDINGS.append(f"[SSH_TEST] {host}: Fallo en conexión SSH - Código: {returncode}, Error: {error_detail}")
            logger.error(f"Fallo en conexión SSH a {host}: código {returncode}, error: {error_detail}")
            return False
    
    def quick_scan(self, host: str, user: str, 
                  key_file: Optional[str] = None, port: int = 22) -> Dict:
        """Escaneo rápido con comandos básicos optimizados"""
        
        FINDINGS.append(f"[REMOTE_QUICK] Iniciando escaneo rápido de {host}")
        logger.info(f"Iniciando escaneo rápido de {host}")
        
        quick_command = """
            echo "=== QUICK_SCAN_START ===";
            echo "Hostname: $(hostname 2>/dev/null || echo 'no disponible')";
            echo "OS: $(uname -a 2>/dev/null || echo 'no disponible')";
            echo "User: $(whoami 2>/dev/null || echo 'no disponible')";
            echo "ID: $(id 2>/dev/null || echo 'no disponible')";
            echo "=== PROCESSES ===";
            ps aux 2>/dev/null | head -15 || echo "ps no disponible";
            echo "=== NETWORK ===";
            netstat -tuln 2>/dev/null | head -10 || ss -tuln 2>/dev/null | head -10 || echo "netstat/ss no disponibles";
            echo "=== SYSTEM_FILES ===";
            ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null || echo "archivos sistema no accesibles";
            echo "=== SUID_CHECK ===";
            find / -perm -4000 2>/dev/null | head -5 || echo "búsqueda SUID falló";
            echo "=== SERVICES ===";
            systemctl list-units --type=service --state=running 2>/dev/null | head -5 || service --status-all 2>/dev/null | head -5 || echo "servicios no disponibles";
            echo "=== QUICK_SCAN_END ===";
        """
        
        stdout, stderr, returncode, custody = self.execute_remote_command(
            host, user, quick_command, key_file, port
        )
        
        if stdout and "QUICK_SCAN_START" in stdout:
            # Análisis básico del escaneo rápido
            self.analyze_quick_scan_output(stdout, host)
            
            evidence = ForensicEvidence(
                timestamp=datetime.datetime.now().isoformat(),
                source_host=host,
                evidence_type="quick_scan",
                hash_sha256=self.calculate_evidence_hash(stdout),
                command_executed=quick_command,
                raw_output=stdout,
                analysis_metadata={
                    "stderr": stderr,
                    "return_code": returncode,
                    "scan_type": "quick",
                    "duration": "optimized"
                },
                chain_of_custody=[custody, f"QUICK_SCAN|{self.session_id}"]
            )
            
            FINDINGS.append(f"[REMOTE_QUICK] Escaneo rápido completado exitosamente para {host}")
            logger.info(f"Escaneo rápido completado para {host}")
            return {"quick_scan": evidence}
        
        else:
            error_msg = stderr or "Sin salida del comando"
            FINDINGS.append(f"[REMOTE_QUICK] Error en escaneo rápido de {host}: {error_msg}")
            logger.error(f"Error en escaneo rápido de {host}: {error_msg}")
            return {}
    
    def analyze_quick_scan_output(self, output: str, host: str):
        """Analiza la salida del escaneo rápido"""
        
        try:
            # Extraer información básica del sistema
            if "Hostname:" in output:
                hostname_line = [line for line in output.split('\n') if 'Hostname:' in line][0]
                hostname = hostname_line.split(':', 1)[1].strip()
                if hostname and hostname != 'no disponible':
                    FINDINGS.append(f"[REMOTE_QUICK] {host}: Hostname remoto: {hostname}")
            
            # Detectar OS
            if "Linux" in output:
                FINDINGS.append(f"[REMOTE_QUICK] {host}: Sistema Linux detectado")
            if "Ubuntu" in output:
                FINDINGS.append(f"[REMOTE_QUICK] {host}: Ubuntu detectado")
            elif "CentOS" in output or "Red Hat" in output:
                FINDINGS.append(f"[REMOTE_QUICK] {host}: Red Hat/CentOS detectado")
            
            # Analizar procesos críticos
            if "root" in output and ("bash" in output or "sh" in output):
                FINDINGS.append(f"[REMOTE_QUICK] {host}: Procesos root con shell detectados")
            
            # Detectar servicios web
            if any(service in output.lower() for service in ["apache", "nginx", "httpd"]):
                FINDINGS.append(f"[REMOTE_QUICK] {host}: Servidor web detectado")
            
            # Detectar bases de datos
            if any(db in output.lower() for db in ["mysql", "postgres", "mongodb"]):
                FINDINGS.append(f"[REMOTE_QUICK] {host}: Servidor de base de datos detectado")
            
            # Analizar puertos abiertos
            dangerous_ports = ["21", "23", "135", "445", "1433", "3389", "5900"]
            open_ports = []
            for port in dangerous_ports:
                if f":{port}" in output:
                    open_ports.append(port)
            
            if open_ports:
                FINDINGS.append(f"[REMOTE_QUICK] {host}: Puertos peligrosos abiertos: {', '.join(open_ports)}")
            
            # Verificar archivos críticos
            if "/etc/shadow" in output and "root" in output:
                FINDINGS.append(f"[REMOTE_QUICK] {host}: Acceso a archivo /etc/shadow confirmado")
            
            # Buscar binarios SUID
            suid_count = output.count("/usr/") + output.count("/bin/")
            if suid_count > 0:
                FINDINGS.append(f"[REMOTE_QUICK] {host}: {suid_count} binarios SUID encontrados")
            
        except Exception as e:
            logger.error(f"Error analizando escaneo rápido de {host}: {e}")
            FINDINGS.append(f"[REMOTE_QUICK_ERROR] {host}: Error en análisis rápido")
    
    def generate_forensic_summary(self) -> Dict:
        """Genera un resumen forense de la sesión"""
        
        summary = {
            "session_id": self.session_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "total_evidence_collected": len(self.evidence_chain),
            "evidence_integrity_hashes": [evidence.hash_sha256 for evidence in self.evidence_chain],
            "hosts_analyzed": list(set([evidence.source_host for evidence in self.evidence_chain])),
            "evidence_types": list(set([evidence.evidence_type for evidence in self.evidence_chain])),
            "chain_of_custody_entries": len([entry for evidence in self.evidence_chain for entry in evidence.chain_of_custody])
        }
        
        logger.info(f"Resumen forense generado: {len(self.evidence_chain)} evidencias de {len(summary['hosts_analyzed'])} hosts")
        FINDINGS.append(f"[FORENSIC_SUMMARY] Sesión {self.session_id}: {summary['total_evidence_collected']} evidencias recopiladas")
        
        return summary
    
    def export_evidence_chain(self, output_file: str = None) -> str:
        """Exporta la cadena de custodia completa"""
        
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"forensic_evidence_chain_{self.session_id}_{timestamp}.json"
        
        try:
            evidence_data = {
                "session_metadata": {
                    "session_id": self.session_id,
                    "export_timestamp": datetime.datetime.now().isoformat(),
                    "total_evidence_items": len(self.evidence_chain),
                    "cyberscope_version": "2.0"
                },
                "evidence_chain": [asdict(evidence) for evidence in self.evidence_chain],
                "summary": self.generate_forensic_summary()
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(evidence_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Cadena de evidencia exportada a: {output_file}")
            FINDINGS.append(f"[FORENSIC_EXPORT] Cadena de evidencia exportada: {output_file}")
            
            return output_file
            
        except Exception as e:
            logger.error(f"Error exportando cadena de evidencia: {e}")
            FINDINGS.append(f"[FORENSIC_EXPORT_ERROR] Error: {str(e)}")
            return None
