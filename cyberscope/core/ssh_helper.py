#!/usr/bin/env python3
"""
Módulo auxiliar para conexiones SSH con múltiples métodos de autenticación
CyberScope Remote Forensic Scanner
"""

import os
import logging
import socket
from typing import Tuple, Optional

# Intentar importar paramiko como respaldo
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    paramiko = None

logger = logging.getLogger(__name__)

class SSHHelper:
    """Helper class para manejo de conexiones SSH con múltiples backends"""
    
    @staticmethod
    def test_connectivity(hostname: str, port: int, timeout: int = 10) -> bool:
        """
        Prueba conectividad básica al puerto SSH
        
        Args:
            hostname: Host objetivo
            port: Puerto SSH
            timeout: Timeout en segundos
            
        Returns:
            bool: True si el puerto está accesible
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((hostname, port))
            sock.close()
            
            if result == 0:
                logger.debug(f"✅ Puerto {port} accesible en {hostname}")
                return True
            else:
                logger.error(f"❌ Puerto {port} no accesible en {hostname}")
                return False
                
        except Exception as e:
            logger.error(f"💥 Error en test de conectividad: {e}")
            return False
    
    @staticmethod
    def validate_key_file(key_file: str) -> Tuple[bool, str]:
        """
        Valida un archivo de clave SSH
        
        Args:
            key_file: Ruta al archivo de clave
            
        Returns:
            Tuple[bool, str]: (es_válido, mensaje_error)
        """
        if not key_file or not key_file.strip():
            return False, "Ruta de archivo de clave vacía"
        
        key_file = key_file.strip()
        
        if not os.path.exists(key_file):
            return False, f"Archivo de clave no encontrado: {key_file}"
        
        if not os.path.isfile(key_file):
            return False, f"La ruta no es un archivo: {key_file}"
        
        # Verificar permisos
        try:
            stat_info = os.stat(key_file)
            mode = oct(stat_info.st_mode)[-3:]
            
            if mode not in ['600', '400']:
                logger.warning(f"⚠️ Archivo de clave tiene permisos inseguros: {mode}")
                # Intentar corregir permisos
                try:
                    os.chmod(key_file, 0o600)
                    logger.info(f"✅ Permisos corregidos a 600")
                except OSError as e:
                    logger.warning(f"⚠️ No se pudieron corregir permisos: {e}")
        
        except OSError as e:
            return False, f"Error verificando permisos: {e}"
        
        # Verificar formato básico del archivo
        try:
            with open(key_file, 'r') as f:
                content = f.read(1024)  # Leer solo el inicio
                
                # Verificar que tiene formato de clave SSH
                key_headers = [
                    '-----BEGIN RSA PRIVATE KEY-----',
                    '-----BEGIN DSA PRIVATE KEY-----',
                    '-----BEGIN EC PRIVATE KEY-----',
                    '-----BEGIN OPENSSH PRIVATE KEY-----',
                    '-----BEGIN PRIVATE KEY-----'
                ]
                
                if not any(header in content for header in key_headers):
                    return False, "El archivo no parece ser una clave SSH válida"
                
        except Exception as e:
            return False, f"Error leyendo archivo de clave: {e}"
        
        return True, "Archivo de clave válido"
    
    @staticmethod
    def test_ssh_auth_paramiko(hostname: str, username: str, password: str = None, 
                              key_file: str = None, port: int = 22, timeout: int = 30) -> Tuple[bool, str]:
        """
        Prueba autenticación SSH usando paramiko (si está disponible)
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            password: Contraseña SSH (opcional)
            key_file: Archivo de clave privada (opcional)
            port: Puerto SSH
            timeout: Timeout en segundos
            
        Returns:
            Tuple[bool, str]: (éxito, mensaje)
        """
        if not PARAMIKO_AVAILABLE:
            return False, "Paramiko no está disponible"
        
        try:
            # Crear cliente SSH
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Configurar timeout
            client.get_transport().set_keepalive(30)
            
            # Intentar conexión
            if key_file and os.path.exists(key_file):
                logger.debug(f"🔑 Intentando autenticación con clave: {key_file}")
                client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    key_filename=key_file,
                    timeout=timeout,
                    banner_timeout=30,
                    auth_timeout=30
                )
            elif password:
                logger.debug(f"🔒 Intentando autenticación con contraseña")
                client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    password=password,
                    timeout=timeout,
                    banner_timeout=30,
                    auth_timeout=30
                )
            else:
                return False, "No se proporcionó método de autenticación"
            
            # Ejecutar comando de prueba
            stdin, stdout, stderr = client.exec_command('echo "SSH_PARAMIKO_TEST_OK"', timeout=10)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            client.close()
            
            if "SSH_PARAMIKO_TEST_OK" in output:
                return True, "Autenticación SSH exitosa con paramiko"
            else:
                return False, f"Comando de prueba falló: {error}"
                
        except paramiko.AuthenticationException:
            return False, "Error de autenticación SSH - credenciales inválidas"
        except paramiko.SSHException as e:
            return False, f"Error SSH: {str(e)}"
        except socket.timeout:
            return False, f"Timeout de conexión SSH ({timeout}s)"
        except Exception as e:
            return False, f"Error inesperado: {str(e)}"
    
    @staticmethod
    def execute_command_paramiko(hostname: str, username: str, command: str,
                                password: str = None, key_file: str = None, 
                                port: int = 22, timeout: int = 30) -> Tuple[str, str, int]:
        """
        Ejecuta un comando remoto usando paramiko
        
        Args:
            hostname: Host objetivo
            username: Usuario SSH
            command: Comando a ejecutar
            password: Contraseña SSH (opcional)
            key_file: Archivo de clave privada (opcional)
            port: Puerto SSH
            timeout: Timeout en segundos
            
        Returns:
            Tuple[str, str, int]: (stdout, stderr, return_code)
        """
        if not PARAMIKO_AVAILABLE:
            return "", "Paramiko no está disponible", -1
        
        try:
            # Crear cliente SSH
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Conectar
            if key_file and os.path.exists(key_file):
                client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    key_filename=key_file,
                    timeout=timeout
                )
            elif password:
                client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    password=password,
                    timeout=timeout
                )
            else:
                return "", "No se proporcionó método de autenticación", -1
            
            # Ejecutar comando
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            
            # Leer resultados
            stdout_data = stdout.read().decode('utf-8', errors='ignore')
            stderr_data = stderr.read().decode('utf-8', errors='ignore')
            return_code = stdout.channel.recv_exit_status()
            
            client.close()
            
            return stdout_data, stderr_data, return_code
            
        except Exception as e:
            logger.error(f"Error ejecutando comando con paramiko: {e}")
            return "", str(e), -1
    
    @staticmethod
    def get_ssh_diagnostics(hostname: str, port: int = 22) -> dict:
        """
        Obtiene información de diagnóstico para troubleshooting SSH
        
        Args:
            hostname: Host objetivo
            port: Puerto SSH
            
        Returns:
            dict: Información de diagnóstico
        """
        diagnostics = {
            'hostname': hostname,
            'port': port,
            'network_reachable': False,
            'ssh_service_detected': False,
            'paramiko_available': PARAMIKO_AVAILABLE,
            'errors': []
        }
        
        try:
            # Test de conectividad básica
            diagnostics['network_reachable'] = SSHHelper.test_connectivity(hostname, port, timeout=10)
            
            if diagnostics['network_reachable']:
                # Intentar detectar servicio SSH
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    sock.connect((hostname, port))
                    
                    # Leer banner SSH
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    if 'SSH' in banner:
                        diagnostics['ssh_service_detected'] = True
                        diagnostics['ssh_banner'] = banner.strip()
                    
                except Exception as e:
                    diagnostics['errors'].append(f"Error detectando servicio SSH: {e}")
            
        except Exception as e:
            diagnostics['errors'].append(f"Error en diagnósticos: {e}")
        
        return diagnostics
    
    @staticmethod
    def suggest_fixes(error_message: str, diagnostics: dict = None) -> list:
        """
        Sugiere soluciones basadas en el mensaje de error
        
        Args:
            error_message: Mensaje de error SSH
            diagnostics: Información de diagnóstico (opcional)
            
        Returns:
            list: Lista de sugerencias
        """
        suggestions = []
        error_lower = error_message.lower()
        
        # Errores de autenticación
        if 'permission denied' in error_lower or 'authentication' in error_lower:
            suggestions.extend([
                "Verificar que el usuario y contraseña/clave sean correctos",
                "Asegurarse de que el archivo de clave privada tenga permisos 600",
                "Verificar que el usuario tenga permisos de login SSH",
                "Revisar la configuración SSH del servidor (/etc/ssh/sshd_config)"
            ])
        
        # Errores de conectividad
        if 'connection refused' in error_lower or 'no route' in error_lower:
            suggestions.extend([
                "Verificar que el servidor esté encendido y accesible",
                "Comprobar que el puerto SSH (generalmente 22) esté abierto",
                "Verificar configuración de firewall en servidor y red",
                "Probar conectividad con: ping {hostname}".format(
                    hostname=diagnostics.get('hostname', 'HOSTNAME') if diagnostics else 'HOSTNAME'
                )
            ])
        
        # Errores de timeout
        if 'timeout' in error_lower:
            suggestions.extend([
                "Aumentar el valor de timeout en la configuración",
                "Verificar latencia de red con: ping {hostname}".format(
                    hostname=diagnostics.get('hostname', 'HOSTNAME') if diagnostics else 'HOSTNAME'
                ),
                "Comprobar que no hay problemas de red intermitentes"
            ])
        
        # Errores de clave
        if 'key' in error_lower or 'publickey' in error_lower:
            suggestions.extend([
                "Verificar que el archivo de clave privada existe y es legible",
                "Asegurar que la clave pública esté en ~/.ssh/authorized_keys del servidor",
                "Verificar permisos: chmod 600 archivo_clave_privada",
                "Probar la clave manualmente: ssh -i clave usuario@servidor"
            ])
        
        # Sugerencias generales si no hay sugerencias específicas
        if not suggestions:
            suggestions.extend([
                "Probar conexión manual: ssh usuario@servidor",
                "Verificar logs del servidor SSH: /var/log/auth.log",
                "Comprobar configuración SSH: /etc/ssh/sshd_config",
                "Revisar que sshpass esté instalado para autenticación por contraseña"
            ])
        
        return suggestions
