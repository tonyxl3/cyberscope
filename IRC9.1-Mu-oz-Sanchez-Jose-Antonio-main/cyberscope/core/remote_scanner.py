#!/usr/bin/env python3
"""
Sistema de Análisis Remoto Forense - Integrado con CyberScope
Versión: 2.0
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
        
        ssh_cmd = self.build_ssh_command(host, user, command, key_file, port)
        
        start_time = datetime.datetime.now()
        logger.info(f"Ejecutando comando forense en {host}: {command[:100]}...")
        FINDINGS.append(f"[SSH_EXEC] {host}: {command[:100]}...")
        
        try:
            result = subprocess.run(
                ssh_cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=self.config["ssh_timeout"]
            )
            
            execution_time = (datetime.datetime.now() - start_time).total_seconds()
            
            # Registrar en cadena de custodia
            custody_entry = f"CMD_EXEC|{host}|{user}|{start_time.isoformat()}|{execution_time}s"
            
            if result.returncode == 0:
                FINDINGS.append(f"[SSH_SUCCESS] {host}: Comando ejecutado exitosamente")
            else:
                FINDINGS.append(f"[SSH_ERROR] {host}: Error en comando (código: {result.returncode})")
            
            return result.stdout, result.stderr, result.returncode, custody_entry
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout en comando remoto: {host}")
            FINDINGS.append(f"[SSH_TIMEOUT] {host}: Timeout en comando SSH")
            return "", "TIMEOUT_ERROR", 124, f"TIMEOUT|{host}|{command[:50]}"
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
        
        ssh_options = [
            "-o StrictHostKeyChecking=no",
            "-o UserKnownHostsFile=/dev/null",
            "-o LogLevel=ERROR",
            f"-o ConnectTimeout={self.config['ssh_timeout']}",
            f"-p {port}"
        ]
        
        if key_file and key_file.strip():
            ssh_options.append(f"-i {key_file}")
            
        ssh_cmd = f"ssh {' '.join(ssh_options)} {user}@{host} '{command}'"
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
        
        forensic_commands = {
            "system_identification": {
                "command": """
                    echo "=== SYSTEM_ID ===";
                    hostname;
                    uname -a;
                    cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || cat /etc/issue;
                    uptime;
                    date;
                    timedatectl status 2>/dev/null;
                """,
                "priority": 1
            },
            
            "user_activity_forensics": {
                "command": """
                    echo "=== USER_FORENSICS ===";
                    whoami;
                    id;
                    last -n 20 2>/dev/null;
                    lastlog 2>/dev/null | head -20;
                    w 2>/dev/null;
                    who -a 2>/dev/null;
                    users 2>/dev/null;
                    cat /etc/passwd | grep -v nologin | grep -v false;
                    sudo -l 2>/dev/null;
                """,
                "priority": 2
            },
            
            "process_memory_analysis": {
                "command": """
                    echo "=== PROCESS_ANALYSIS ===";
                    ps auxf 2>/dev/null;
                    ps -eo pid,ppid,user,cmd,lstart,etime --sort=-start_time 2>/dev/null;
                    pstree -p 2>/dev/null;
                    lsof -i 2>/dev/null | head -50;
                """,
                "priority": 1
            },
            
            "network_forensics": {
                "command": """
                    echo "=== NETWORK_FORENSICS ===";
                    ip addr show 2>/dev/null || ifconfig 2>/dev/null;
                    ip route show 2>/dev/null || route -n 2>/dev/null;
                    arp -a 2>/dev/null;
                    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null;
                    netstat -tupln 2>/dev/null || ss -tupln 2>/dev/null;
                    iptables -L -n 2>/dev/null;
                """,
                "priority": 1
            },
            
            "service_security_analysis": {
                "command": """
                    echo "=== SERVICE_SECURITY ===";
                    systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null;
                    systemctl list-unit-files --type=service --state=enabled 2>/dev/null;
                    chkconfig --list 2>/dev/null;
                    crontab -l 2>/dev/null;
                    cat /etc/crontab 2>/dev/null;
                    ls -la /etc/cron* 2>/dev/null;
                """,
                "priority": 2
            },
            
            "file_system_forensics": {
                "command": """
                    echo "=== FILESYSTEM_FORENSICS ===";
                    df -h 2>/dev/null;
                    mount 2>/dev/null;
                    lsblk 2>/dev/null;
                    find /tmp -type f -mtime -1 2>/dev/null | head -20;
                    find /var/tmp -type f -mtime -1 2>/dev/null | head -20;
                    find / -perm -4000 -type f 2>/dev/null | head -30;
                    find / -perm -2000 -type f 2>/dev/null | head -30;
                """,
                "priority": 2
            },
            
            "security_configuration": {
                "command": """
                    echo "=== SECURITY_CONFIG ===";
                    cat /etc/ssh/sshd_config 2>/dev/null | grep -E '^[^#]';
                    cat /etc/sudoers 2>/dev/null | grep -E '^[^#]';
                    cat /etc/hosts.allow 2>/dev/null;
                    cat /etc/hosts.deny 2>/dev/null;
                    sestatus 2>/dev/null;
                    getenforce 2>/dev/null;
                    ufw status 2>/dev/null;
                """,
                "priority": 2
            },
            
            "log_analysis": {
                "command": """
                    echo "=== LOG_ANALYSIS ===";
                    tail -50 /var/log/auth.log 2>/dev/null || tail -50 /var/log/secure 2>/dev/null;
                    tail -50 /var/log/syslog 2>/dev/null || tail -50 /var/log/messages 2>/dev/null;
                    grep -i "failed\\|error\\|warning" /var/log/auth.log 2>/dev/null | tail -20;
                    grep -i "sudo" /var/log/auth.log 2>/dev/null | tail -10;
                    dmesg 2>/dev/null | tail -30;
                """,
                "priority": 3
            },
            
            "application_analysis": {
                "command": """
                    echo "=== APPLICATION_ANALYSIS ===";
                    dpkg -l 2>/dev/null | grep -E '(apache|nginx|mysql|php|ssh|ftp)' || rpm -qa 2>/dev/null | grep -E '(apache|nginx|mysql|php|ssh|ftp)';
                    apache2 -v 2>/dev/null || httpd -v 2>/dev/null;
                    nginx -v 2>/dev/null;
                    mysql --version 2>/dev/null;
                    php --version 2>/dev/null;
                    python --version 2>/dev/null;
                    python3 --version 2>/dev/null;
                    java -version 2>&1;
                """,
                "priority": 3
            }
        }
        
        evidence_collection = {}
        
        # Ejecutar comandos por prioridad
        for category, cmd_info in sorted(forensic_commands.items(), 
                                       key=lambda x: x[1]["priority"]):
            
            logger.info(f"Recopilando evidencia: {category}")
            FINDINGS.append(f"[REMOTE_EVIDENCE] {host}: Recopilando {category}")
            
            stdout, stderr, returncode, custody = self.execute_remote_command(
                host, user, cmd_info["command"], key_file, port
            )
            
            if stdout or stderr:
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
                        "execution_priority": cmd_info["priority"]
                    },
                    chain_of_custody=[custody, f"PROCESSED|{self.session_id}"]
                )
                
                evidence_collection[category] = evidence
                self.evidence_chain.append(evidence)
                
                # Agregar hallazgos específicos
                self.analyze_evidence_for_findings(category, stdout, host)
        
        FINDINGS.append(f"[REMOTE_SCAN] Análisis forense completado para {host}")
        return evidence_collection
    
    def analyze_evidence_for_findings(self, category: str, output: str, host: str):
        """Analiza evidencia y genera hallazgos específicos"""
        
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
    
    def analyze_user_activity(self, output: str, host: str):
        """Analiza actividad de usuarios"""
        
        if "root" in output and "pts/" in output:
            FINDINGS.append(f"[REMOTE_FINDING] {host}: Actividad de login como root detectada")
        
        if "NOPASSWD" in output:
            FINDINGS.append(f"[REMOTE_FINDING] {host}: Usuario configurado con sudo sin contraseña")
        
        # Buscar usuarios sospechosos
        lines = output.split('\n')
        for line in lines:
            if '/bin/bash' in line and 'root' not in line:
                user = line.split(':')[0]
                FINDINGS.append(f"[REMOTE_USER] {host}: Usuario con shell bash: {user}")
    
    def analyze_network_security(self, output: str, host: str):
        """Analiza seguridad de red"""
        
        # Puertos peligrosos abiertos
        dangerous_ports = ["23", "135", "445", "1433", "3389", "5900"]
        for port in dangerous_ports:
            if f":{port}" in output:
                FINDINGS.append(f"[REMOTE_VULN] {host}: Puerto peligroso {port} abierto")
        
        # Buscar conexiones sospechosas
        if "ESTABLISHED" in output:
            lines = output.split('\n')
            for line in lines:
                if "ESTABLISHED" in line and any(port in line for port in dangerous_ports):
                    FINDINGS.append(f"[REMOTE_CONNECTION] {host}: Conexión activa sospechosa: {line.strip()}")
    
    def analyze_services(self, output: str, host: str):
        """Analiza servicios en ejecución"""
        
        suspicious_services = ["telnet", "rsh", "rlogin", "ftp"]
        for service in suspicious_services:
            if service in output.lower():
                FINDINGS.append(f"[REMOTE_SERVICE] {host}: Servicio inseguro detectado: {service}")
        
        # Buscar servicios web
        if "apache" in output.lower() or "nginx" in output.lower() or "httpd" in output.lower():
            FINDINGS.append(f"[REMOTE_WEB] {host}: Servidor web detectado")
        
        # Buscar bases de datos
        if "mysql" in output.lower() or "postgres" in output.lower():
            FINDINGS.append(f"[REMOTE_DB] {host}: Servidor de base de datos detectado")
    
    def analyze_filesystem(self, output: str, host: str):
        """Analiza sistema de archivos"""
        
        # Buscar archivos SUID peligrosos
        dangerous_suid = ["nmap", "vim", "find", "bash", "more", "less", "nano"]
        for binary in dangerous_suid:
            if binary in output:
                FINDINGS.append(f"[REMOTE_SUID] {host}: Binario SUID peligroso: {binary}")
        
        # Buscar archivos temporales recientes
        if "/tmp/" in output or "/var/tmp/" in output:
            lines = output.split('\n')
            temp_files = [line for line in lines if '/tmp/' in line or '/var/tmp/' in line]
            if temp_files:
                FINDINGS.append(f"[REMOTE_TEMP] {host}: {len(temp_files)} archivos temporales recientes")
    
    def analyze_security_config(self, output: str, host: str):
        """Analiza configuración de seguridad"""
        
        # SSH Configuration
        if "PermitRootLogin yes" in output:
            FINDINGS.append(f"[REMOTE_SSH] {host}: Login root por SSH habilitado")
        
        if "PasswordAuthentication yes" in output:
            FINDINGS.append(f"[REMOTE_SSH] {host}: Autenticación por contraseña habilitada")
        
        if "Protocol 1" in output:
            FINDINGS.append(f"[REMOTE_SSH] {host}: Protocolo SSH v1 habilitado (inseguro)")
        
        # Firewall status
        if "inactive" in output.lower() or "disabled" in output.lower():
            FINDINGS.append(f"[REMOTE_FIREWALL] {host}: Firewall deshabilitado")
    
    def analyze_logs(self, output: str, host: str):
        """Analiza logs del sistema"""
        
        # Buscar intentos de login fallidos
        failed_logins = output.count("Failed password")
        if failed_logins > 0:
            FINDINGS.append(f"[REMOTE_AUTH] {host}: {failed_logins} intentos de login fallidos detectados")
        
        # Buscar uso de sudo
        sudo_usage = output.count("sudo:")
        if sudo_usage > 0:
            FINDINGS.append(f"[REMOTE_SUDO] {host}: {sudo_usage} usos de sudo detectados")
        
        # Buscar errores del sistema
        if "error" in output.lower() or "critical" in output.lower():
            error_lines = [line for line in output.split('\n') if 'error' in line.lower() or 'critical' in line.lower()]
            FINDINGS.append(f"[REMOTE_ERROR] {host}: {len(error_lines)} errores del sistema detectados")
    
    def analyze_processes(self, output: str, host: str):
        """Analiza procesos en ejecución"""
        
        # Buscar procesos sospechosos
        suspicious_processes = ["nc", "netcat", "ncat", "socat", "python -c", "perl -e", "bash -i"]
        for process in suspicious_processes:
            if process in output.lower():
                FINDINGS.append(f"[REMOTE_PROCESS] {host}: Proceso sospechoso detectado: {process}")
        
        # Buscar procesos con alta CPU
        lines = output.split('\n')
        for line in lines:
            if '%CPU' not in line and len(line.split()) > 2:
                try:
                    cpu_usage = float(line.split()[2])
                    if cpu_usage > 80.0:
                        process_name = ' '.join(line.split()[10:])[:50]
                        FINDINGS.append(f"[REMOTE_CPU] {host}: Proceso con alta CPU ({cpu_usage}%): {process_name}")
                except (ValueError, IndexError):
                    continue
    
    def vulnerability_assessment(self, host: str, user: str, 
                               key_file: Optional[str] = None, port: int = 22) -> Dict:
        """Evaluación de vulnerabilidades específica"""
        
        FINDINGS.append(f"[REMOTE_VULN] Iniciando evaluación de vulnerabilidades en {host}")
        
        vuln_checks = {
            "ssh_security": """
                echo "=== SSH_VULNS ===";
                ssh -V 2>&1;
                cat /etc/ssh/sshd_config | grep -E '(PermitRootLogin|PasswordAuthentication|Protocol|Ciphers)';
                netstat -tulpn | grep :22 2>/dev/null || ss -tulpn | grep :22 2>/dev/null;
            """,
            
            "web_vulnerabilities": """
                echo "=== WEB_VULNS ===";
                find /var/www -name "*.php" -exec grep -l "mysql_connect\\|eval\\|\$_GET\\|\$_POST" {} \\; 2>/dev/null | head -10;
                find /var/www -name ".git" -type d 2>/dev/null;
                find /var/www -name "config.php" -o -name ".env" 2>/dev/null | head -10;
                curl -s -I localhost/.git/config 2>/dev/null;
            """,
            
            "privilege_escalation": """
                echo "=== PRIVESC_VULNS ===";
                find / -perm -4000 2>/dev/null | grep -E "(nmap|vim|find|bash|more|less|nano)";
                sudo -l 2>/dev/null;
                cat /etc/sudoers 2>/dev/null | grep NOPASSWD;
                find /etc -writable -type f 2>/dev/null;
            """,
            
            "database_security": """
                echo "=== DB_VULNS ===";
                mysql -e "SELECT version();" 2>/dev/null;
                find / -name "*.sql" -type f 2>/dev/null | head -10;
                netstat -tulpn | grep -E "(3306|5432|27017)" 2>/dev/null || ss -tulpn | grep -E "(3306|5432|27017)" 2>/dev/null;
                ps aux | grep -E "(mysql|postgres|mongo)" | grep -v grep;
            """
        }
        
        vulnerability_evidence = {}
        
        for vuln_type, command in vuln_checks.items():
            stdout, stderr, returncode, custody = self.execute_remote_command(
                host, user, command, key_file, port
            )
            
            # Analizar salida para vulnerabilidades
            vuln_analysis = self.analyze_vulnerability_output(vuln_type, stdout, host)
            
            vulnerability_evidence[vuln_type] = {
                "raw_output": stdout,
                "vulnerabilities_found": vuln_analysis,
                "evidence_hash": self.calculate_evidence_hash(stdout),
                "custody": custody
            }
        
        FINDINGS.append(f"[REMOTE_VULN] Evaluación de vulnerabilidades completada para {host}")
        return vulnerability_evidence
    
    def analyze_vulnerability_output(self, vuln_type: str, output: str, host: str) -> List[str]:
        """Analiza salida para identificar vulnerabilidades"""
        vulnerabilities = []
        
        if vuln_type == "ssh_security":
            if "PermitRootLogin yes" in output:
                vulnerabilities.append("ROOT_LOGIN_ENABLED")
                FINDINGS.append(f"[REMOTE_VULN] {host}: SSH - Login root habilitado")
            if "PasswordAuthentication yes" in output:
                vulnerabilities.append("PASSWORD_AUTH_ENABLED")
                FINDINGS.append(f"[REMOTE_VULN] {host}: SSH - Autenticación por contraseña habilitada")
            if "Protocol 1" in output:
                vulnerabilities.append("SSH_PROTOCOL_1_ENABLED")
                FINDINGS.append(f"[REMOTE_VULN] {host}: SSH - Protocolo v1 habilitado")
                
        elif vuln_type == "web_vulnerabilities":
            if "mysql_connect" in output:
                vulnerabilities.append("DEPRECATED_MYSQL_FUNCTIONS")
                FINDINGS.append(f"[REMOTE_VULN] {host}: Web - Funciones MySQL obsoletas")
            if "eval" in output:
                vulnerabilities.append("CODE_INJECTION_RISK")
                FINDINGS.append(f"[REMOTE_VULN] {host}: Web - Riesgo de inyección de código")
            if ".git" in output:
                vulnerabilities.append("GIT_DIRECTORY_EXPOSED")
                FINDINGS.append(f"[REMOTE_VULN] {host}: Web - Directorio .git expuesto")
                
        elif vuln_type == "privilege_escalation":
            dangerous_suid = ["nmap", "vim", "find", "bash", "more", "less"]
            for binary in dangerous_suid:
                if binary in output:
                    vulnerabilities.append(f"SUID_{binary.upper()}_FOUND")
                    FINDINGS.append(f"[REMOTE_VULN] {host}: PrivEsc - SUID {binary} encontrado")
            if "NOPASSWD" in output:
                vulnerabilities.append("SUDO_NOPASSWD_CONFIGURED")
                FINDINGS.append(f"[REMOTE_VULN] {host}: PrivEsc - Sudo sin contraseña configurado")
        
        elif vuln_type == "database_security":
            if "3306" in output:  # MySQL
                vulnerabilities.append("MYSQL_EXPOSED")
                FINDINGS.append(f"[REMOTE_VULN] {host}: DB - MySQL expuesto")
            if "5432" in output:  # PostgreSQL
                vulnerabilities.append("POSTGRESQL_EXPOSED")
                FINDINGS.append(f"[REMOTE_VULN] {host}: DB - PostgreSQL expuesto")
            if "27017" in output:  # MongoDB
                vulnerabilities.append("MONGODB_EXPOSED")
                FINDINGS.append(f"[REMOTE_VULN] {host}: DB - MongoDB expuesto")
        
        return vulnerabilities
    
    def test_ssh_connection(self, host: str, user: str, 
                          key_file: Optional[str] = None, port: int = 22) -> bool:
        """Prueba la conexión SSH antes del análisis"""
        
        test_command = "echo 'SSH_CONNECTION_TEST'"
        stdout, stderr, returncode, _ = self.execute_remote_command(
            host, user, test_command, key_file, port
        )
        
        if returncode == 0 and "SSH_CONNECTION_TEST" in stdout:
            FINDINGS.append(f"[SSH_TEST] {host}: Conexión SSH exitosa")
            return True
        else:
            FINDINGS.append(f"[SSH_TEST] {host}: Fallo en conexión SSH - {stderr}")
            return False
    
    def quick_scan(self, host: str, user: str, 
                  key_file: Optional[str] = None, port: int = 22) -> Dict:
        """Escaneo rápido con comandos básicos"""
        
        FINDINGS.append(f"[REMOTE_QUICK] Iniciando escaneo rápido de {host}")
        
        quick_command = """
            echo "=== QUICK_SCAN ===";
            hostname; uname -a; whoami; id;
            ps aux | head -20;
            netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null;
            ls -la /etc/passwd /etc/shadow 2>/dev/null;
            find / -perm -4000 2>/dev/null | head -10;
            systemctl list-units --type=service --state=running 2>/dev/null | head -10;
        """
        
        stdout, stderr, returncode, custody = self.execute_remote_command(
            host, user, quick_command, key_file, port
        )
        
        if stdout:
            # Análisis básico
            self.analyze_evidence_for_findings("quick_scan", stdout, host)
            
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
                    "scan_type": "quick"
                },
                chain_of_custody=[custody, f"QUICK_SCAN|{self.session_id}"]
            )
            
            FINDINGS.append(f"[REMOTE_QUICK] Escaneo rápido completado para {host}")
            return {"quick_scan": evidence}
        
        FINDINGS.append(f"[REMOTE_QUICK] Error en escaneo rápido de {host}")
        return {}