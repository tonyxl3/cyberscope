#!/usr/bin/env python3
"""
Configuración para el Sistema de Análisis Remoto Forense - CORREGIDO
"""

import yaml
import os
from pathlib import Path
from typing import Dict, List, Optional

class RemoteForensicConfig:
    """Maneja la configuración del sistema forense remoto"""
    
    def __init__(self, config_file: str = "remote_forensic.yaml"):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Carga configuración desde archivo YAML"""
        default_config = self.get_default_config()
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        # Fusionar configuración de manera inteligente
                        default_config = self.merge_configs(default_config, user_config)
        except Exception as e:
            print(f"Error cargando configuración: {e}")
        
        # Validar y normalizar configuración
        self.validate_config(default_config)
        return default_config
    
    def merge_configs(self, default: Dict, user: Dict) -> Dict:
        """Fusiona configuraciones de manera recursiva"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                default[key] = self.merge_configs(default[key], value)
            else:
                default[key] = value
        return default
    
    def validate_config(self, config: Dict):
        """Valida la configuración y establece valores por defecto"""
        
        # Asegurar que existe configuración SSH con nombres consistentes
        if 'ssh' not in config:
            config['ssh'] = {}
        
        ssh_defaults = {
            'timeout': 50,
            'ssh_timeout': 50,  # Alias para compatibilidad
            'max_retries': 3,
            'key_exchange_timeout': 10,
            'connection_pool_size': 5,
            'default_port': 22
        }
        
        for key, default_value in ssh_defaults.items():
            if key not in config['ssh']:
                config['ssh'][key] = default_value
        
        # Asegurar coherencia entre timeout y ssh_timeout
        if config['ssh']['timeout'] != config['ssh']['ssh_timeout']:
            # Usar el valor de timeout como principal
            config['ssh']['ssh_timeout'] = config['ssh']['timeout']
        
        # Configuraciones de nivel superior para compatibilidad
        config['ssh_timeout'] = config['ssh']['timeout']
        config['max_concurrent'] = config.get('analysis', {}).get('max_concurrent_hosts', 3)
        
        # Validar directorios
        evidence_dir = config.get('evidence', {}).get('directory', './forensic_evidence')
        config['evidence_dir'] = evidence_dir
        
        # Crear directorio de evidencia si no existe
        try:
            os.makedirs(evidence_dir, exist_ok=True)
        except Exception as e:
            print(f"Advertencia: No se pudo crear directorio de evidencia {evidence_dir}: {e}")
    
    def get_default_config(self) -> Dict:
        """Configuración por defecto del sistema"""
        return {
            # Configuración SSH
            "ssh": {
                "timeout": 50,
                "ssh_timeout": 50,  # Alias para compatibilidad
                "max_retries": 3,
                "key_exchange_timeout": 10,
                "connection_pool_size": 5,
                "default_port": 22,
                "strict_host_key_checking": False,
                "batch_mode": True
            },
            
            # Configuración de Evidencia
            "evidence": {
                "directory": "./forensic_evidence",
                "preserve_raw": True,
                "compress_artifacts": True,
                "hash_algorithm": "sha256",
                "chain_of_custody": True,
                "timestamp_format": "%Y%m%d_%H%M%S",
                "max_file_size": "100MB"
            },
            
            # Configuración de Análisis
            "analysis": {
                "max_concurrent_hosts": 3,
                "priority_based_execution": True,
                "deep_scan_enabled": True,
                "vulnerability_scanning": True,
                "log_analysis_depth": 1000,
                "command_timeout": 50,
                "retry_failed_commands": True
            },
            
            # Configuración de Reportes
            "reporting": {
                "format": ["json", "pdf"],
                "include_raw_evidence": True,
                "executive_summary": True,
                "vulnerability_scoring": True,
                "timeline_analysis": True,
                "compress_reports": False
            },
            
            # Configuración de Logging
            "logging": {
                "level": "INFO",
                "file_rotation": True,
                "max_file_size": "10MB",
                "backup_count": 5,
                "syslog_enabled": False,
                "console_output": True
            },
            
            # Configuración de Seguridad
            "security": {
                "encrypt_evidence": True,
                "secure_deletion": True,
                "access_control": True,
                "audit_trail": True,
                "sanitize_commands": True
            },
            
            # Perfiles de Análisis Predefinidos
            "profiles": {
                "quick": [
                    "system_identification",
                    "user_activity_forensics",
                    "network_forensics"
                ],
                "standard": [
                    "system_identification",
                    "user_activity_forensics",
                    "process_memory_analysis",
                    "network_forensics",
                    "service_security_analysis",
                    "security_configuration"
                ],
                "comprehensive": [
                    "system_identification",
                    "user_activity_forensics",
                    "process_memory_analysis",
                    "network_forensics",
                    "service_security_analysis",
                    "file_system_forensics",
                    "security_configuration",
                    "log_analysis",
                    "application_analysis"
                ],
                "vulnerability": [
                    "ssh_security",
                    "web_vulnerabilities",
                    "privilege_escalation",
                    "database_security",
                    "network_security"
                ]
            },
            
            # Comandos personalizados optimizados
            "custom_commands": {
                "web_server_check": "ps aux | grep -E '(apache|nginx|httpd)' | grep -v grep || echo 'No web servers'",
                "database_check": "ps aux | grep -E '(mysql|postgres|mongo)' | grep -v grep || echo 'No databases'",
                "suspicious_files": "find /tmp /var/tmp -type f -mtime -1 2>/dev/null | head -20 || echo 'No recent temp files'",
                "network_connections": "netstat -tupln 2>/dev/null || ss -tupln 2>/dev/null || echo 'Network info unavailable'",
                "system_info": "uname -a && hostname && whoami && id",
                "security_check": "find / -perm -4000 2>/dev/null | head -10 || echo 'SUID search failed'",
                "service_status": "systemctl list-units --type=service --state=running 2>/dev/null | head -10 || service --status-all 2>/dev/null | head -10",
                "log_errors": "grep -i error /var/log/syslog 2>/dev/null | tail -10 || grep -i error /var/log/messages 2>/dev/null | tail -10"
            },
            
            # Configuración de timeouts específicos
            "timeouts": {
                "ssh_connection": 30,
                "command_execution": 30,
                "file_transfer": 60,
                "vulnerability_scan": 120
            },
            
            # Configuración de reintentos
            "retry": {
                "max_attempts": 3,
                "delay_seconds": 5,
                "exponential_backoff": True
            }
        }
    
    def save_config(self, config: Dict = None):
        """Guarda configuración actual en archivo"""
        config_to_save = config or self.config
        
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(config_to_save, f, default_flow_style=False, indent=2)
            print(f"Configuración guardada en {self.config_file}")
        except Exception as e:
            print(f"Error guardando configuración: {e}")
    
    def get_ssh_config(self) -> Dict:
        """Obtiene configuración SSH normalizada"""
        ssh_config = self.config.get("ssh", {})
        
        # Asegurar que existen todas las claves necesarias
        required_keys = {
            'timeout': 50,
            'ssh_timeout': 50,
            'max_retries': 3,
            'default_port': 22
        }
        
        for key, default_value in required_keys.items():
            if key not in ssh_config:
                ssh_config[key] = default_value
        
        return ssh_config
    
    def get_analysis_profile(self, profile_name: str) -> List[str]:
        """Obtiene comandos de un perfil de análisis"""
        profiles = self.config.get("profiles", {})
        return profiles.get(profile_name, profiles.get("standard", []))
    
    def get_custom_command(self, command_name: str) -> Optional[str]:
        """Obtiene comando personalizado"""
        custom_commands = self.config.get("custom_commands", {})
        return custom_commands.get(command_name)
    
    def get_timeout(self, timeout_type: str) -> int:
        """Obtiene timeout específico con fallback"""
        timeouts = self.config.get("timeouts", {})
        ssh_config = self.config.get("ssh", {})
        
        timeout_mapping = {
            'ssh_connection': timeouts.get('ssh_connection', ssh_config.get('timeout', 30)),
            'command_execution': timeouts.get('command_execution', 30),
            'ssh_timeout': ssh_config.get('timeout', 30),
            'default': 30
        }
        
        return timeout_mapping.get(timeout_type, timeout_mapping['default'])
    
    def validate_host_config(self, host_config: Dict) -> bool:
        """Valida configuración de un host específico"""
        required_fields = ['hostname', 'username']
        
        for field in required_fields:
            if field not in host_config or not host_config[field]:
                print(f"Error: Campo requerido '{field}' faltante en configuración de host")
                return False
        
        # Validar puerto
        port = host_config.get('port', 22)
        if not isinstance(port, int) or port < 1 or port > 65535:
            print(f"Error: Puerto inválido {port}")
            return False
        
        # Validar archivo de clave si está especificado
        key_file = host_config.get('key_file')
        if key_file and not os.path.exists(key_file):
            print(f"Advertencia: Archivo de clave SSH no encontrado: {key_file}")
        
        return True
    
    def create_sample_config(self):
        """Crea archivo de configuración de ejemplo"""
        sample_config = self.get_default_config()
        
        # Agregar comentarios y ejemplos
        sample_config["_comments"] = {
            "description": "Configuración de CyberScope Remote Forensic Scanner v2.0",
            "ssh": "Configuración para conexiones SSH remotas",
            "evidence": "Configuración para manejo de evidencia forense",
            "analysis": "Configuración para tipos de análisis y ejecución",
            "profiles": "Perfiles predefinidos de análisis forense",
            "custom_commands": "Comandos personalizados para análisis específicos",
            "timeouts": "Configuración de timeouts para diferentes operaciones",
            "security": "Configuraciones de seguridad y auditoría"
        }
        
        # Agregar ejemplos de hosts
        sample_config["example_hosts"] = [
            {
                "hostname": "192.168.1.100",
                "username": "forensic_user",
                "key_file": "/path/to/private/key",
                "port": 22,
                "description": "Servidor web principal"
            },
            {
                "hostname": "server.example.com",
                "username": "admin",
                "port": 2222,
                "description": "Servidor de base de datos"
            }
        ]
        
        sample_file = "remote_forensic_sample.yaml"
        try:
            with open(sample_file, 'w') as f:
                yaml.dump(sample_config, f, default_flow_style=False, indent=2)
            print(f"Archivo de configuración de ejemplo creado: {sample_file}")
        except Exception as e:
            print(f"Error creando archivo de ejemplo: {e}")
    
    def get_evidence_config(self) -> Dict:
        """Obtiene configuración de evidencia"""
        return self.config.get("evidence", {})
    
    def get_security_config(self) -> Dict:
        """Obtiene configuración de seguridad"""
        return self.config.get("security", {})
    
    def get_retry_config(self) -> Dict:
        """Obtiene configuración de reintentos"""
        return self.config.get("retry", {})

class HostManager:
    """Maneja listas de hosts para análisis en lote"""
    
    def __init__(self, config: RemoteForensicConfig = None):
        self.config = config or RemoteForensicConfig()
        self.hosts = []
    
    def load_hosts_from_file(self, hosts_file: str) -> List[Dict]:
        """Carga hosts desde archivo CSV o YAML"""
        hosts = []
        
        if not os.path.exists(hosts_file):
            print(f"Error: Archivo de hosts no encontrado: {hosts_file}")
            return hosts
        
        try:
            if hosts_file.endswith('.yaml') or hosts_file.endswith('.yml'):
                hosts = self.load_hosts_yaml(hosts_file)
            elif hosts_file.endswith('.csv'):
                hosts = self.load_hosts_csv(hosts_file)
            else:
                print(f"Formato de archivo no soportado: {hosts_file}")
                return hosts
            
            # Validar cada host
            valid_hosts = []
            for host in hosts:
                if self.config.validate_host_config(host):
                    valid_hosts.append(host)
                else:
                    print(f"Host inválido omitido: {host.get('hostname', 'desconocido')}")
            
            print(f"Cargados {len(valid_hosts)} hosts válidos de {len(hosts)} totales")
            return valid_hosts
            
        except Exception as e:
            print(f"Error cargando hosts: {e}")
            return []
    
    def load_hosts_yaml(self, yaml_file: str) -> List[Dict]:
        """Carga hosts desde archivo YAML"""
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
                hosts = data.get('hosts', [])
                
                # Normalizar configuración de hosts
                for host in hosts:
                    # Establecer valores por defecto
                    host.setdefault('port', 22)
                    host.setdefault('priority', 1)
                    host.setdefault('profile', 'standard')
                    host.setdefault('description', '')
                    
                return hosts
        except Exception as e:
            print(f"Error cargando hosts desde YAML: {e}")
            return []
    
    def load_hosts_csv(self, csv_file: str) -> List[Dict]:
        """Carga hosts desde archivo CSV"""
        import csv
        hosts = []
        
        try:
            with open(csv_file, 'r') as f:
                # Detectar automáticamente el delimitador
                sample = f.read(1024)
                f.seek(0)
                sniffer = csv.Sniffer()
                delimiter = sniffer.sniff(sample).delimiter
                
                reader = csv.DictReader(f, delimiter=delimiter)
                for row_num, row in enumerate(reader, 1):
                    try:
                        host_config = {
                            'hostname': row['hostname'].strip(),
                            'username': row['username'].strip(),
                            'key_file': row.get('key_file', '').strip() or None,
                            'port': int(row.get('port', 22)),
                            'priority': int(row.get('priority', 1)),
                            'profile': row.get('profile', 'standard').strip(),
                            'description': row.get('description', '').strip()
                        }
                        hosts.append(host_config)
                    except (ValueError, KeyError) as e:
                        print(f"Error en fila {row_num}: {e}")
                        continue
                        
        except Exception as e:
            print(f"Error cargando hosts desde CSV: {e}")
        
        return hosts
    
    def create_sample_hosts_file(self, format_type: str = "yaml"):
        """Crea archivo de ejemplo para hosts"""
        
        sample_hosts = [
            {
                'hostname': '192.168.1.100',
                'username': 'forensic_admin',
                'key_file': '/home/user/.ssh/forensic_key',
                'port': 22,
                'priority': 1,
                'profile': 'comprehensive',
                'description': 'Servidor web principal - análisis completo'
            },
            {
                'hostname': 'database.internal.com',
                'username': 'db_forensic',
                'key_file': '/home/user/.ssh/db_key',
                'port': 2222,
                'priority': 2,
                'profile': 'standard',
                'description': 'Servidor de base de datos - análisis estándar'
            },
            {
                'hostname': '10.0.0.50',
                'username': 'admin',
                'key_file': None,  # Usar autenticación por contraseña
                'port': 22,
                'priority': 3,
                'profile': 'quick',
                'description': 'Servidor de pruebas - escaneo rápido'
            }
        ]
        
        if format_type == "yaml":
            filename = "hosts_sample.yaml"
            try:
                hosts_data = {
                    '_comments': {
                        'description': 'Archivo de configuración de hosts para CyberScope',
                        'hostname': 'IP o nombre de host del servidor objetivo',
                        'username': 'Usuario SSH para conectarse',
                        'key_file': 'Ruta al archivo de clave privada SSH (null para contraseña)',
                        'port': 'Puerto SSH (por defecto 22)',
                        'priority': 'Prioridad de análisis (1=alta, 3=baja)',
                        'profile': 'Perfil de análisis (quick/standard/comprehensive)',
                        'description': 'Descripción del servidor'
                    },
                    'hosts': sample_hosts
                }
                
                with open(filename, 'w') as f:
                    yaml.dump(hosts_data, f, default_flow_style=False, indent=2)
                print(f"Archivo de hosts de ejemplo creado: {filename}")
            except Exception as e:
                print(f"Error creando archivo YAML: {e}")
        
        elif format_type == "csv":
            import csv
            filename = "hosts_sample.csv"
            try:
                with open(filename, 'w', newline='') as f:
                    fieldnames = ['hostname', 'username', 'key_file', 'port', 'priority', 'profile', 'description']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for host in sample_hosts:
                        writer.writerow(host)
                print(f"Archivo de hosts de ejemplo creado: {filename}")
            except Exception as e:
                print(f"Error creando archivo CSV: {e}")
    
    def validate_hosts_batch(self, hosts: List[Dict]) -> List[Dict]:
        """Valida una lista de hosts en lote"""
        valid_hosts = []
        invalid_hosts = []
        
        for host in hosts:
            if self.config.validate_host_config(host):
                valid_hosts.append(host)
            else:
                invalid_hosts.append(host.get('hostname', 'desconocido'))
        
        if invalid_hosts:
            print(f"Hosts inválidos omitidos: {', '.join(invalid_hosts)}")
        
        return valid_hosts
    
    def sort_hosts_by_priority(self, hosts: List[Dict]) -> List[Dict]:
        """Ordena hosts por prioridad"""
        return sorted(hosts, key=lambda x: x.get('priority', 1))
    
    def filter_hosts_by_profile(self, hosts: List[Dict], profile: str) -> List[Dict]:
        """Filtra hosts por perfil de análisis"""
        return [host for host in hosts if host.get('profile', 'standard') == profile]
