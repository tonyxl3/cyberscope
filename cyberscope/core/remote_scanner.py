#!/usr/bin/env python3
"""
Sistema de Análisis Forense Remoto SSH - CyberScope v2.0
Análisis forense sin rastros en servidores remotos
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

class RemoteForensicScanner:
    """Scanner forense remoto que no deja rastros en el servidor objetivo"""
    
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
        self.ssh_timeout = self.config.get('ssh_timeout', 30)
        self.max_concurrent = self.config.get('max_concurrent', 3)
        self.evidence_dir = self.config.get('evidence_dir', './forensic_evidence')
        
        # Crear directorio de evidencia
        os.makedirs(self.evidence_dir, exist_ok=True)
        
        logger.info(f"Scanner forense remoto inicializado - Sesión: {self.session_id}")
        FINDINGS.append(f"[REMOTE_INIT] Sesión forense iniciada: {self.session_id}")
    
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
            ssh_cmd.extend(['echo', '"SSH_CONNECTION_TEST_OK"'])
            
            logger.debug(f"Comando SSH de prueba: {' '.join(ssh_cmd[:5])}...")  # No mostrar credenciales
            
            # Ejecutar comando de prueba
            use_input = password if password and not key_file and not self._check_sshpass_available() else None
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=self.ssh_timeout,
                input=use_input
            )
            
            if result.returncode == 0 and "SSH_CONNECTION_TEST_OK" in result.stdout:
                logger.info(f"Conexión SSH exitosa a {hostname}:{port}")
                FINDINGS.append(f"[SSH_TEST] Conexión exitosa a {hostname}:{port}")
                return True
            else:
                logger.error(f"Fallo en prueba SSH: {result.stderr}")
                FINDINGS.append(f"[SSH_ERROR] Fallo de conexión: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout en conexión SSH a {hostname}:{port}")
            FINDINGS.append(f"[SSH_TIMEOUT] Timeout conectando a {hostname}:{port}")
            return False
        except Exception as e:
            logger.error(f"Error en prueba SSH: {e}")
            FINDINGS.append(f"[SSH_ERROR] Error de conexión: {str(e)}")
            return False
    
    def _test_network_connectivity(self, hostname: str, port: int) -> bool:
        """Prueba conectividad de red básica"""
        try:
            # Test de ping
            ping_result = subprocess.run(
                ['ping', '-c', '1', '-W', '5', hostname],
                capture_output=True,
                timeout=10
            )
            
            if ping_result.returncode != 0:
                logger.warning(f"Ping falló a {hostname}, pero continuando...")
            
            # Test de conectividad TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((hostname, port))
            sock.close()
            
            if result == 0:
                logger.info(f"Puerto {port} accesible en {hostname}")
                return True
            else:
                logger.error(f"Puerto {port} no accesible en {hostname}")
                FINDINGS.append(f"[NETWORK_ERROR] Puerto {port} no accesible en {hostname}")
                return False
                
        except Exception as e:
            logger.error(f"Error en test de conectividad: {e}")
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
        ssh_cmd = [
            'ssh',
            '-o', 'ConnectTimeout=30',
            '-o', 'ServerAliveInterval=60',
            '-o', 'ServerAliveCountMax=3',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-p', str(port)
        ]
        
        # Configurar autenticación
        if key_file and os.path.exists(key_file):
            ssh_cmd.extend(['-i', key_file])
            ssh_cmd.extend(['-o', 'BatchMode=yes'])  # No solicitar contraseña si hay clave
            logger.debug(f"Usando autenticación por clave: {key_file}")
        elif password:
            # Para contraseña, usar sshpass si está disponible
            if self._check_sshpass_available():
                ssh_cmd = ['sshpass', '-p', password] + ssh_cmd
                ssh_cmd.extend(['-o', 'BatchMode=yes'])
                logger.debug("Usando autenticación por contraseña con sshpass")
            else:
                ssh_cmd.extend(['-o', 'BatchMode=no'])  # Permitir entrada interactiva
                logger.debug("Usando autenticación por contraseña interactiva")
        else:
            ssh_cmd.extend(['-o', 'BatchMode=no'])  # Permitir entrada interactiva
        
        # Agregar usuario y host
        ssh_cmd.append(f"{username}@{hostname}")
        
        return ssh_cmd
    
    def _check_sshpass_available(self) -> bool:
        """Verifica si sshpass está disponible"""
        try:
            result = subprocess.run(['which', 'sshpass'], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
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
            # Construir comando SSH
            ssh_cmd = self._build_ssh_command(hostname, username, key_file, port, password)
            ssh_cmd.append(command)
            
            logger.debug(f"Ejecutando comando remoto: {command[:50]}...")
            
            use_input = password if (password and not key_file and not self._check_sshpass_available()) else None
            
            # Ejecutar comando
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=use_input
            )
            
            # Registrar evidencia
            self._record_evidence(hostname, command, result.stdout, result.stderr, result.returncode)
            
            return result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired:
            error_msg = f"Timeout ejecutando comando: {command[:50]}"
            logger.error(error_msg)
            FINDINGS.append(f"[CMD_TIMEOUT] {error_msg}")
            return "", error_msg, -1
        except Exception as e:
            error_msg = f"Error ejecutando comando: {str(e)}"
            logger.error(error_msg)
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
    
    def quick_scan(self, hostname: str, username: str, key_file: str = None, 
                   port: int = 22, password: str = None) -> Dict:
        """
        Escaneo rápido del sistema remoto
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            key_file: Archivo de clave privada
            port: Puerto SSH
            password: Contraseña SSH
            
        Returns:
            Dict: Evidencia recopilada
        """
        logger.info(f"Iniciando escaneo rápido de {hostname}")
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
        
        for category, command in quick_commands.items():
            try:
                stdout, stderr, return_code = self._execute_remote_command(
                    hostname, username, command, key_file, port, password
                )
                
                if return_code == 0 and stdout.strip():
                    evidence[category] = {
                        "command": command,
                        "output": stdout.strip(),
                        "timestamp": datetime.now().isoformat()
                    }
                    FINDINGS.append(f"[QUICK_EVIDENCE] {category}: {len(stdout)} bytes recopilados")
                else:
                    FINDINGS.append(f"[QUICK_ERROR] Error en {category}: {stderr}")
                    
            except Exception as e:
                logger.error(f"Error en comando {category}: {e}")
                FINDINGS.append(f"[QUICK_ERROR] Error en {category}: {str(e)}")
        
        FINDINGS.append(f"[QUICK_COMPLETE] Escaneo rápido completado: {len(evidence)} categorías")
        return evidence
    
    def comprehensive_system_analysis(self, hostname: str, username: str, 
                                    key_file: str = None, port: int = 22, 
                                    password: str = None) -> Dict:
        """
        Análisis forense completo del sistema
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            key_file: Archivo de clave privada
            port: Puerto SSH
            password: Contraseña SSH
            
        Returns:
            Dict: Evidencia forense completa
        """
        logger.info(f"Iniciando análisis forense completo de {hostname}")
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
        
        for category, commands in forensic_commands.items():
            evidence[category] = {}
            FINDINGS.append(f"[FORENSIC_CATEGORY] Analizando: {category}")
            
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
                        FINDINGS.append(f"[FORENSIC_EVIDENCE] {subcategory}: {len(stdout)} bytes")
                    else:
                        FINDINGS.append(f"[FORENSIC_WARNING] {subcategory}: Sin datos o error")
                        
                except Exception as e:
                    logger.error(f"Error en {subcategory}: {e}")
                    FINDINGS.append(f"[FORENSIC_ERROR] {subcategory}: {str(e)}")
        
        FINDINGS.append(f"[FORENSIC_COMPLETE] Análisis forense completado: {len(evidence)} categorías")
        return evidence
    
    def vulnerability_assessment(self, hostname: str, username: str, 
                               key_file: str = None, port: int = 22, 
                               password: str = None) -> Dict:
        """
        Evaluación de vulnerabilidades del sistema remoto
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            key_file: Archivo de clave privada
            port: Puerto SSH
            password: Contraseña SSH
            
        Returns:
            Dict: Vulnerabilidades encontradas
        """
        logger.info(f"Iniciando evaluación de vulnerabilidades en {hostname}")
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
        
        for category, checks in vuln_checks.items():
            vulnerabilities[category] = {
                "vulnerabilities_found": [],
                "evidence": {}
            }
            
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
                        
                        if vulns:
                            for vuln in vulns:
                                FINDINGS.append(f"[VULNERABILITY] {category}: {vuln}")
                        
                except Exception as e:
                    logger.error(f"Error en check {check_name}: {e}")
                    FINDINGS.append(f"[VULN_ERROR] {check_name}: {str(e)}")
        
        total_vulns = sum(len(v["vulnerabilities_found"]) for v in vulnerabilities.values())
        FINDINGS.append(f"[VULN_COMPLETE] Evaluación completada: {total_vulns} vulnerabilidades encontradas")
        
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
            
            logger.info(f"Cadena de evidencia exportada: {output_file}")
            FINDINGS.append(f"[EVIDENCE_EXPORT] Cadena de evidencia exportada: {output_file}")
            
            return output_file
            
        except Exception as e:
            logger.error(f"Error exportando cadena de evidencia: {e}")
            FINDINGS.append(f"[EVIDENCE_ERROR] Error exportando evidencia: {str(e)}")
            return None
