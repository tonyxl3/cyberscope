#!/usr/bin/env python3
"""
Sistema de Análisis Remoto Forense - CORREGIDO para autenticación por contraseña
"""

import subprocess
import json
import os
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import uuid
import tempfile
import shlex

from .utils import FINDINGS, logger
from .remote_config import RemoteForensicConfig

class RemoteForensicScanner:
    """Scanner forense remoto que no deja rastros en el servidor objetivo"""
    
    def __init__(self, config: Dict = None):
        """Inicializa el scanner remoto"""
        self.config = config or {}
        self.session_id = str(uuid.uuid4())[:8]
        self.evidence_chain = []
        self.start_time = datetime.now()
        
        # Configuración SSH mejorada
        self.ssh_options = [
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=30',
            '-o', 'ServerAliveCountMax=3',
            '-o', 'BatchMode=no',  # Permitir interacción para contraseñas
            '-o', 'PasswordAuthentication=yes',
            '-o', 'PubkeyAuthentication=yes',
            '-o', 'PreferredAuthentications=publickey,password'
        ]
        
        logger.info(f"Scanner remoto inicializado - Sesión: {self.session_id}")
    
    def test_ssh_connection(self, hostname: str, username: str, key_file: str = None, port: int = 22) -> bool:
        """
        Prueba la conexión SSH de manera más robusta
        """
        try:
            # Construir comando SSH básico
            ssh_cmd = ['ssh'] + self.ssh_options + ['-p', str(port)]
            
            # Agregar clave privada si se proporciona
            if key_file and key_file.strip() and os.path.exists(key_file.strip()):
                ssh_cmd.extend(['-i', key_file.strip()])
                logger.info(f"Usando clave privada: {key_file}")
            else:
                logger.info("Usando autenticación por contraseña")
            
            # Agregar destino
            ssh_cmd.append(f"{username}@{hostname}")
            ssh_cmd.append('echo "SSH_CONNECTION_TEST_OK"')
            
            logger.info(f"Probando conexión SSH: {' '.join(ssh_cmd[:6])}... {username}@{hostname}")
            
            # Ejecutar con timeout más largo para permitir entrada de contraseña
            try:
                result = subprocess.run(
                    ssh_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,  # Timeout más largo
                    input=None  # No enviar input automáticamente
                )
                
                # Verificar si la conexión fue exitosa
                if result.returncode == 0 and "SSH_CONNECTION_TEST_OK" in result.stdout:
                    logger.info(f"Conexión SSH exitosa a {hostname}:{port}")
                    FINDINGS.append(f"[SSH_TEST] Conexión exitosa a {hostname}:{port}")
                    return True
                else:
                    # Log detallado del error
                    error_msg = result.stderr.strip() if result.stderr else "Error desconocido"
                    logger.error(f"Fallo en conexión SSH: {error_msg}")
                    FINDINGS.append(f"[SSH_ERROR] Fallo de conexión: {error_msg}")
                    
                    # Intentar diagnóstico adicional
                    self._diagnose_ssh_connection(hostname, port)
                    return False
                    
            except subprocess.TimeoutExpired:
                logger.error(f"Timeout en conexión SSH a {hostname}:{port}")
                FINDINGS.append(f"[SSH_TIMEOUT] Timeout de conexión a {hostname}:{port}")
                return False
                
        except Exception as e:
            logger.error(f"Error probando conexión SSH: {e}")
            FINDINGS.append(f"[SSH_EXCEPTION] Error de conexión: {str(e)}")
            return False
    
    def _diagnose_ssh_connection(self, hostname: str, port: int):
        """Diagnóstica problemas de conexión SSH"""
        try:
            # Verificar conectividad básica
            ping_result = subprocess.run(
                ['ping', '-c', '1', '-W', '3', hostname],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if ping_result.returncode == 0:
                FINDINGS.append(f"[SSH_DIAG] Host {hostname} es alcanzable por ping")
            else:
                FINDINGS.append(f"[SSH_DIAG] Host {hostname} NO es alcanzable por ping")
            
            # Verificar puerto SSH
            nc_result = subprocess.run(
                ['nc', '-z', '-v', hostname, str(port)],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if nc_result.returncode == 0:
                FINDINGS.append(f"[SSH_DIAG] Puerto {port} está abierto en {hostname}")
            else:
                FINDINGS.append(f"[SSH_DIAG] Puerto {port} NO está abierto en {hostname}")
                
        except Exception as e:
            logger.debug(f"Error en diagnóstico SSH: {e}")
    
    def execute_remote_command(self, hostname: str, username: str, command: str, 
                             key_file: str = None, port: int = 22, timeout: int = 30) -> Tuple[bool, str, str]:
        """
        Ejecuta un comando remoto por SSH de manera mejorada
        """
        try:
            # Construir comando SSH
            ssh_cmd = ['ssh'] + self.ssh_options + ['-p', str(port)]
            
            # Agregar clave privada si se proporciona
            if key_file and key_file.strip() and os.path.exists(key_file.strip()):
                ssh_cmd.extend(['-i', key_file.strip()])
            
            # Agregar destino y comando
            ssh_cmd.append(f"{username}@{hostname}")
            ssh_cmd.append(command)
            
            # Log del comando (sin mostrar detalles sensibles)
            safe_cmd = f"ssh {username}@{hostname} '{command[:50]}...'"
            logger.debug(f"Ejecutando: {safe_cmd}")
            
            # Ejecutar comando
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            success = result.returncode == 0
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            
            # Registrar evidencia
            self._record_evidence(hostname, command, stdout, stderr, success)
            
            return success, stdout, stderr
            
        except subprocess.TimeoutExpired:
            error_msg = f"Timeout ejecutando comando en {hostname}"
            logger.error(error_msg)
            FINDINGS.append(f"[CMD_TIMEOUT] {error_msg}")
            return False, "", error_msg
            
        except Exception as e:
            error_msg = f"Error ejecutando comando remoto: {str(e)}"
            logger.error(error_msg)
            FINDINGS.append(f"[CMD_ERROR] {error_msg}")
            return False, "", error_msg
    
    def _record_evidence(self, hostname: str, command: str, stdout: str, stderr: str, success: bool):
        """Registra evidencia de comandos ejecutados"""
        evidence_entry = {
            'timestamp': datetime.now().isoformat(),
            'hostname': hostname,
            'command': command,
            'success': success,
            'stdout_hash': hashlib.sha256(stdout.encode()).hexdigest() if stdout else None,
            'stderr_hash': hashlib.sha256(stderr.encode()).hexdigest() if stderr else None,
            'session_id': self.session_id
        }
        
        self.evidence_chain.append(evidence_entry)
    
    def quick_scan(self, hostname: str, username: str, key_file: str = None, port: int = 22) -> Dict:
        """Escaneo rápido del sistema remoto"""
        FINDINGS.append(f"[REMOTE_QUICK] Iniciando escaneo rápido de {hostname}")
        
        evidence = {}
        
        # Comandos básicos para escaneo rápido
        quick_commands = {
            'system_info': 'uname -a && hostname && whoami && id',
            'uptime': 'uptime',
            'disk_usage': 'df -h | head -10',
            'memory_info': 'free -h',
            'network_interfaces': 'ip addr show 2>/dev/null || ifconfig 2>/dev/null | head -20',
            'running_processes': 'ps aux | head -15',
            'listening_ports': 'netstat -tulpn 2>/dev/null | head -10 || ss -tulpn 2>/dev/null | head -10'
        }
        
        for category, command in quick_commands.items():
            try:
                success, stdout, stderr = self.execute_remote_command(
                    hostname, username, command, key_file, port, timeout=15
                )
                
                if success and stdout:
                    evidence[category] = {
                        'command': command,
                        'output': stdout,
                        'timestamp': datetime.now().isoformat()
                    }
                    FINDINGS.append(f"[REMOTE_EVIDENCE] {category}: {len(stdout)} caracteres recopilados")
                else:
                    FINDINGS.append(f"[REMOTE_FAILED] {category}: {stderr or 'Sin salida'}")
                    
            except Exception as e:
                logger.error(f"Error en comando {category}: {e}")
                FINDINGS.append(f"[REMOTE_ERROR] {category}: {str(e)}")
        
        FINDINGS.append(f"[REMOTE_QUICK] Escaneo rápido completado: {len(evidence)} categorías")
        return evidence
    
    def comprehensive_system_analysis(self, hostname: str, username: str, key_file: str = None, port: int = 22) -> Dict:
        """Análisis comprehensivo del sistema remoto"""
        FINDINGS.append(f"[REMOTE_COMPREHENSIVE] Iniciando análisis comprehensivo de {hostname}")
        
        evidence = {}
        
        # Comandos organizados por categorías
        comprehensive_commands = {
            'system_identification': {
                'os_info': 'cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || uname -a',
                'kernel_info': 'uname -r && cat /proc/version 2>/dev/null',
                'hostname_info': 'hostname && hostname -f 2>/dev/null',
                'system_uptime': 'uptime && who -b 2>/dev/null'
            },
            
            'user_activity_forensics': {
                'current_users': 'who && w',
                'last_logins': 'last -n 20 2>/dev/null || lastlog | head -20 2>/dev/null',
                'user_accounts': 'cat /etc/passwd | head -20',
                'sudo_users': 'getent group sudo 2>/dev/null || getent group wheel 2>/dev/null',
                'login_history': 'grep -i "accepted\\|failed" /var/log/auth.log 2>/dev/null | tail -10 || grep -i "accepted\\|failed" /var/log/secure 2>/dev/null | tail -10'
            },
            
            'process_memory_analysis': {
                'running_processes': 'ps auxf | head -30',
                'process_tree': 'pstree -p 2>/dev/null || ps -ef --forest | head -20',
                'memory_usage': 'free -h && cat /proc/meminfo | head -10',
                'cpu_info': 'cat /proc/cpuinfo | grep -E "(processor|model name|cpu MHz)" | head -10',
                'load_average': 'cat /proc/loadavg && vmstat 1 2 2>/dev/null'
            },
            
            'network_forensics': {
                'network_interfaces': 'ip addr show 2>/dev/null || ifconfig',
                'routing_table': 'ip route show 2>/dev/null || route -n 2>/dev/null',
                'listening_services': 'netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null',
                'active_connections': 'netstat -tupln 2>/dev/null | head -20 || ss -tupln 2>/dev/null | head -20',
                'arp_table': 'arp -a 2>/dev/null || ip neigh show 2>/dev/null'
            },
            
            'service_security_analysis': {
                'running_services': 'systemctl list-units --type=service --state=running 2>/dev/null | head -15 || service --status-all 2>/dev/null | head -15',
                'cron_jobs': 'crontab -l 2>/dev/null || echo "No user crontab"',
                'system_cron': 'ls -la /etc/cron* 2>/dev/null | head -10',
                'ssh_config': 'grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)" /etc/ssh/sshd_config 2>/dev/null'
            },
            
            'file_system_forensics': {
                'disk_usage': 'df -h',
                'mount_points': 'mount | head -15',
                'recent_files': 'find /tmp /var/tmp -type f -mtime -1 2>/dev/null | head -10 || echo "No recent temp files"',
                'suid_files': 'find / -perm -4000 2>/dev/null | head -10 || echo "SUID search failed"',
                'world_writable': 'find / -type f -perm -002 2>/dev/null | head -5 || echo "World writable search failed"'
            },
            
            'security_configuration': {
                'firewall_status': 'iptables -L -n 2>/dev/null | head -20 || ufw status 2>/dev/null || firewall-cmd --list-all 2>/dev/null',
                'selinux_status': 'getenforce 2>/dev/null || echo "SELinux not available"',
                'apparmor_status': 'aa-status 2>/dev/null || echo "AppArmor not available"',
                'fail2ban_status': 'fail2ban-client status 2>/dev/null || echo "Fail2ban not available"'
            },
            
            'log_analysis': {
                'system_logs': 'tail -20 /var/log/syslog 2>/dev/null || tail -20 /var/log/messages 2>/dev/null',
                'auth_logs': 'tail -20 /var/log/auth.log 2>/dev/null || tail -20 /var/log/secure 2>/dev/null',
                'kernel_logs': 'dmesg | tail -10 2>/dev/null',
                'error_logs': 'grep -i error /var/log/syslog 2>/dev/null | tail -5 || grep -i error /var/log/messages 2>/dev/null | tail -5'
            },
            
            'application_analysis': {
                'web_servers': 'ps aux | grep -E "(apache|nginx|httpd)" | grep -v grep || echo "No web servers"',
                'databases': 'ps aux | grep -E "(mysql|postgres|mongo)" | grep -v grep || echo "No databases"',
                'docker_containers': 'docker ps 2>/dev/null || echo "Docker not available"',
                'installed_packages': 'dpkg -l 2>/dev/null | head -10 || rpm -qa 2>/dev/null | head -10 || echo "Package info unavailable"'
            }
        }
        
        # Ejecutar comandos por categoría
        for category, commands in comprehensive_commands.items():
            evidence[category] = {}
            FINDINGS.append(f"[REMOTE_CATEGORY] Analizando: {category}")
            
            for subcategory, command in commands.items():
                try:
                    success, stdout, stderr = self.execute_remote_command(
                        hostname, username, command, key_file, port, timeout=20
                    )
                    
                    if success and stdout:
                        evidence[category][subcategory] = {
                            'command': command,
                            'output': stdout,
                            'timestamp': datetime.now().isoformat(),
                            'success': True
                        }
                        FINDINGS.append(f"[REMOTE_SUCCESS] {subcategory}: {len(stdout)} caracteres")
                    else:
                        evidence[category][subcategory] = {
                            'command': command,
                            'error': stderr or 'Sin salida',
                            'timestamp': datetime.now().isoformat(),
                            'success': False
                        }
                        FINDINGS.append(f"[REMOTE_FAILED] {subcategory}: {stderr or 'Sin salida'}")
                        
                except Exception as e:
                    logger.error(f"Error en {subcategory}: {e}")
                    FINDINGS.append(f"[REMOTE_ERROR] {subcategory}: {str(e)}")
                    evidence[category][subcategory] = {
                        'command': command,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat(),
                        'success': False
                    }
        
        FINDINGS.append(f"[REMOTE_COMPREHENSIVE] Análisis completado: {len(evidence)} categorías")
        return evidence
    
    def vulnerability_assessment(self, hostname: str, username: str, key_file: str = None, port: int = 22) -> Dict:
        """Evaluación de vulnerabilidades del sistema remoto"""
        FINDINGS.append(f"[REMOTE_VULN] Iniciando evaluación de vulnerabilidades en {hostname}")
        
        vulnerabilities = {}
        
        # Categorías de vulnerabilidades a evaluar
        vuln_categories = {
            'ssh_security': {
                'root_login_check': 'grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null',
                'password_auth_check': 'grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null',
                'ssh_version': 'ssh -V 2>&1',
                'ssh_users': 'grep "^AllowUsers\\|^DenyUsers" /etc/ssh/sshd_config 2>/dev/null || echo "No user restrictions"'
            },
            
            'web_vulnerabilities': {
                'web_server_version': 'apache2 -v 2>/dev/null || nginx -v 2>&1 || httpd -v 2>/dev/null || echo "No web server"',
                'web_config_files': 'find /etc -name "*.conf" -path "*/apache*" -o -path "*/nginx*" 2>/dev/null | head -5',
                'web_processes': 'ps aux | grep -E "(apache|nginx|httpd)" | grep -v grep'
            },
            
            'privilege_escalation': {
                'sudo_config': 'sudo -l 2>/dev/null || echo "Cannot check sudo permissions"',
                'suid_binaries': 'find / -perm -4000 2>/dev/null | head -15',
                'world_writable_dirs': 'find / -type d -perm -002 2>/dev/null | head -10',
                'passwd_permissions': 'ls -la /etc/passwd /etc/shadow 2>/dev/null'
            },
            
            'database_security': {
                'mysql_processes': 'ps aux | grep mysql | grep -v grep || echo "MySQL not running"',
                'postgres_processes': 'ps aux | grep postgres | grep -v grep || echo "PostgreSQL not running"',
                'database_files': 'find /var/lib -name "*.db" -o -name "*.sql" 2>/dev/null | head -5 || echo "No database files found"'
            },
            
            'network_security': {
                'open_ports': 'netstat -tulpn 2>/dev/null | grep LISTEN | head -10 || ss -tulpn 2>/dev/null | grep LISTEN | head -10',
                'firewall_rules': 'iptables -L 2>/dev/null | head -15 || echo "Cannot check iptables"',
                'network_services': 'systemctl list-units --type=service | grep -E "(ssh|ftp|telnet|http)" 2>/dev/null'
            }
        }
        
        # Ejecutar evaluaciones de vulnerabilidades
        for category, checks in vuln_categories.items():
            vulnerabilities[category] = {
                'vulnerabilities_found': [],
                'checks_performed': {},
                'risk_level': 'Low'
            }
            
            FINDINGS.append(f"[VULN_CATEGORY] Evaluando: {category}")
            
            for check_name, command in checks.items():
                try:
                    success, stdout, stderr = self.execute_remote_command(
                        hostname, username, command, key_file, port, timeout=15
                    )
                    
                    vulnerabilities[category]['checks_performed'][check_name] = {
                        'command': command,
                        'output': stdout if success else stderr,
                        'success': success,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Analizar resultados para identificar vulnerabilidades
                    vulns_found = self._analyze_vulnerability_output(category, check_name, stdout, stderr)
                    vulnerabilities[category]['vulnerabilities_found'].extend(vulns_found)
                    
                    if success:
                        FINDINGS.append(f"[VULN_CHECK] {check_name}: Completado")
                    else:
                        FINDINGS.append(f"[VULN_FAILED] {check_name}: {stderr or 'Sin salida'}")
                        
                except Exception as e:
                    logger.error(f"Error en verificación {check_name}: {e}")
                    FINDINGS.append(f"[VULN_ERROR] {check_name}: {str(e)}")
            
            # Calcular nivel de riesgo basado en vulnerabilidades encontradas
            vuln_count = len(vulnerabilities[category]['vulnerabilities_found'])
            if vuln_count >= 3:
                vulnerabilities[category]['risk_level'] = 'High'
            elif vuln_count >= 1:
                vulnerabilities[category]['risk_level'] = 'Medium'
            else:
                vulnerabilities[category]['risk_level'] = 'Low'
        
        total_vulns = sum(len(cat['vulnerabilities_found']) for cat in vulnerabilities.values())
        FINDINGS.append(f"[REMOTE_VULN] Evaluación completada: {total_vulns} vulnerabilidades encontradas")
        
        return vulnerabilities
    
    def _analyze_vulnerability_output(self, category: str, check_name: str, stdout: str, stderr: str) -> List[str]:
        """Analiza la salida de comandos para identificar vulnerabilidades específicas"""
        vulnerabilities = []
        
        if not stdout:
            return vulnerabilities
        
        stdout_lower = stdout.lower()
        
        # Análisis específico por categoría
        if category == 'ssh_security':
            if check_name == 'root_login_check' and 'permitrootlogin yes' in stdout_lower:
                vulnerabilities.append("Root login habilitado por SSH - Alto riesgo de seguridad")
            elif check_name == 'password_auth_check' and 'passwordauthentication yes' in stdout_lower:
                vulnerabilities.append("Autenticación por contraseña habilitada - Riesgo de ataques de fuerza bruta")
            elif check_name == 'ssh_version' and any(old_version in stdout_lower for old_version in ['openssh_6', 'openssh_5', 'openssh_4']):
                vulnerabilities.append("Versión de SSH desactualizada - Posibles vulnerabilidades conocidas")
        
        elif category == 'privilege_escalation':
            if check_name == 'suid_binaries' and any(dangerous in stdout_lower for dangerous in ['/bin/su', '/usr/bin/sudo', '/bin/mount']):
                vulnerabilities.append("Binarios SUID peligrosos encontrados - Posible escalación de privilegios")
            elif check_name == 'world_writable_dirs' and '/tmp' in stdout_lower:
                vulnerabilities.append("Directorios escribibles por todos encontrados - Riesgo de escalación")
        
        elif category == 'network_security':
            if check_name == 'open_ports':
                dangerous_ports = ['21', '23', '25', '53', '80', '135', '139', '445', '1433', '3306', '5432']
                for port in dangerous_ports:
                    if f':{port} ' in stdout or f':{port}\t' in stdout:
                        vulnerabilities.append(f"Puerto {port} abierto - Posible superficie de ataque")
        
        elif category == 'web_vulnerabilities':
            if check_name == 'web_server_version':
                if any(old_version in stdout_lower for old_version in ['apache/2.2', 'nginx/1.0', 'nginx/1.1']):
                    vulnerabilities.append("Servidor web desactualizado - Vulnerabilidades conocidas posibles")
        
        return vulnerabilities
    
    def export_evidence_chain(self, output_file: str) -> str:
        """Exporta la cadena de evidencia forense"""
        try:
            evidence_data = {
                'session_id': self.session_id,
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_commands': len(self.evidence_chain),
                'evidence_chain': self.evidence_chain,
                'integrity_hash': self._calculate_evidence_integrity()
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(evidence_data, f, indent=2, ensure_ascii=False)
            
            FINDINGS.append(f"[EVIDENCE_EXPORT] Cadena de evidencia exportada: {output_file}")
            logger.info(f"Cadena de evidencia exportada: {output_file}")
            
            return output_file
            
        except Exception as e:
            logger.error(f"Error exportando cadena de evidencia: {e}")
            FINDINGS.append(f"[EVIDENCE_ERROR] Error exportando evidencia: {str(e)}")
            return None
    
    def _calculate_evidence_integrity(self) -> str:
        """Calcula hash de integridad de toda la evidencia"""
        evidence_string = json.dumps(self.evidence_chain, sort_keys=True)
        return hashlib.sha256(evidence_string.encode()).hexdigest()
    
    def cleanup_session(self):
        """Limpia recursos de la sesión"""
        try:
            # Limpiar archivos temporales si los hay
            temp_files = getattr(self, '_temp_files', [])
            for temp_file in temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except:
                    pass
            
            logger.info(f"Sesión {self.session_id} limpiada")
            
        except Exception as e:
            logger.error(f"Error limpiando sesión: {e}")