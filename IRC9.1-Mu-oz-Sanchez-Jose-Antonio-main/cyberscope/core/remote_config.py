#!/usr/bin/env python3
"""
Configuración para el Sistema de Análisis Remoto Forense
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
                        default_config.update(user_config)
        except Exception as e:
            print(f"Error cargando configuración: {e}")
        
        return default_config
    
    def get_default_config(self) -> Dict:
        """Configuración por defecto del sistema"""
        return {
            # Configuración SSH
            "ssh": {
                "timeout": 45,
                "max_retries": 3,
                "key_exchange_timeout": 10,
                "connection_pool_size": 5,
                "default_port": 22
            },
            
            # Configuración de Evidencia
            "evidence": {
                "directory": "./forensic_evidence",
                "preserve_raw": True,
                "compress_artifacts": True,
                "hash_algorithm": "sha256",
                "chain_of_custody": True,
                "timestamp_format": "%Y%m%d_%H%M%S"
            },
            
            # Configuración de Análisis
            "analysis": {
                "max_concurrent_hosts": 3,
                "priority_based_execution": True,
                "deep_scan_enabled": True,
                "vulnerability_scanning": True,
                "log_analysis_depth": 1000
            },
            
            # Configuración de Reportes
            "reporting": {
                "format": ["json", "markdown"],
                "include_raw_evidence": True,
                "executive_summary": True,
                "vulnerability_scoring": True,
                "timeline_analysis": True
            },
            
            # Configuración de Logging
            "logging": {
                "level": "INFO",
                "file_rotation": True,
                "max_file_size": "10MB",
                "backup_count": 5,
                "syslog_enabled": False
            },
            
            # Configuración de Seguridad
            "security": {
                "encrypt_evidence": True,
                "secure_deletion": True,
                "access_control": True,
                "audit_trail": True
            },
            
            # Perfiles de Análisis Predefinidos
            "profiles": {
                "basic": [
                    "system_identification",
                    "user_activity_forensics",
                    "network_forensics"
                ],
                "standard": [
                    "system_identification",
                    "user_activity_forensics",
                    "process_memory_analysis",
                    "network_forensics",
                    "service_security_analysis"
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
                ]
            },
            
            # Comandos personalizados
            "custom_commands": {
                "web_server_check": "ps aux | grep -E '(apache|nginx|httpd)' | grep -v grep",
                "database_check": "ps aux | grep -E '(mysql|postgres|mongo)' | grep -v grep",
                "suspicious_files": "find /tmp /var/tmp -type f -mtime -1 2>/dev/null",
                "network_connections": "netstat -tupln 2>/dev/null || ss -tupln 2>/dev/null"
            }
        }
    
    def save_config(self, config: Dict = None):
        """Guarda configuración actual en archivo"""
        config_to_save = config or self.config
        
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(config_to_save, f, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Error guardando configuración: {e}")
    
    def get_ssh_config(self) -> Dict:
        """Obtiene configuración SSH"""
        return self.config.get("ssh", {})
    
    def get_analysis_profile(self, profile_name: str) -> List[str]:
        """Obtiene comandos de un perfil de análisis"""
        profiles = self.config.get("profiles", {})
        return profiles.get(profile_name, profiles.get("standard", []))
    
    def get_custom_command(self, command_name: str) -> Optional[str]:
        """Obtiene comando personalizado"""
        custom_commands = self.config.get("custom_commands", {})
        return custom_commands.get(command_name)
    
    def create_sample_config(self):
        """Crea archivo de configuración de ejemplo"""
        sample_config = self.get_default_config()
        
        # Agregar comentarios y ejemplos
        sample_config["_comments"] = {
            "ssh": "Configuración para conexiones SSH",
            "evidence": "Configuración para manejo de evidencia forense",
            "analysis": "Configuración para tipos de análisis",
            "profiles": "Perfiles predefinidos de análisis"
        }
        
        sample_file = "remote_forensic_sample.yaml"
        try:
            with open(sample_file, 'w') as f:
                yaml.dump(sample_config, f, default_flow_style=False, indent=2)
            print(f"Archivo de configuración de ejemplo creado: {sample_file}")
        except Exception as e:
            print(f"Error creando archivo de ejemplo: {e}")

class HostManager:
    """Maneja listas de hosts para análisis en lote"""
    
    def __init__(self):
        self.hosts = []
    
    def load_hosts_from_file(self, hosts_file: str) -> List[Dict]:
        """Carga hosts desde archivo CSV o YAML"""
        hosts = []
        
        if hosts_file.endswith('.yaml') or hosts_file.endswith('.yml'):
            hosts = self.load_hosts_yaml(hosts_file)
        elif hosts_file.endswith('.csv'):
            hosts = self.load_hosts_csv(hosts_file)
        else:
            print(f"Formato de archivo no soportado: {hosts_file}")
        
        return hosts
    
    def load_hosts_yaml(self, yaml_file: str) -> List[Dict]:
        """Carga hosts desde archivo YAML"""
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
                return data.get('hosts', [])
        except Exception as e:
            print(f"Error cargando hosts desde YAML: {e}")
            return []
    
    def load_hosts_csv(self, csv_file: str) -> List[Dict]:
        """Carga hosts desde archivo CSV"""
        import csv
        hosts = []
        
        try:
            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    host_config = {
                        'hostname': row['hostname'],
                        'username': row['username'],
                        'key_file': row.get('key_file', None),
                        'port': int(row.get('port', 22)),
                        'priority': int(row.get('priority', 1)),
                        'profile': row.get('profile', 'standard'),
                        'description': row.get('description', '')
                    }
                    hosts.append(host_config)
        except Exception as e:
            print(f"Error cargando hosts desde CSV: {e}")
        
        return hosts
    
    def create_sample_hosts_file(self, format_type: str = "yaml"):
        """Crea archivo de ejemplo para hosts"""
        
        sample_hosts = [
            {
                'hostname': '192.168.1.100',
                'username': 'admin',
                'key_file': '/path/to/private/key',
                'port': 22,
                'priority': 1,
                'profile': 'comprehensive',
                'description': 'Servidor web principal'
            },
            {
                'hostname': 'db.example.com',
                'username': 'dbadmin',
                'key_file': None,  # Usar autenticación por contraseña
                'port': 2222,
                'priority': 2,
                'profile': 'standard',
                'description': 'Servidor de base de datos'
            }
        ]
        
        if format_type == "yaml":
            filename = "hosts_sample.yaml"
            try:
                with open(filename, 'w') as f:
                    yaml.dump({'hosts': sample_hosts}, f, default_flow_style=False, indent=2)
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