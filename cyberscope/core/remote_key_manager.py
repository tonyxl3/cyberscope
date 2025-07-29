#!/usr/bin/env python3
"""
Gestor de Claves SSH Remotas para CyberScope
Automatiza la generación y distribución de claves SSH para análisis forense remoto
"""

import os
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def ensure_ssh_key_and_push(hostname: str, username: str, password: str, port: int = 22) -> bool:
    """
    Asegura que existe una clave SSH y la copia automáticamente al host remoto.
    
    Esta función:
    1. Verifica si existe /root/.ssh/id_rsa
    2. Si no existe, genera un nuevo par de claves SSH RSA de 4096 bits
    3. Usa sshpass para copiar automáticamente la clave pública al servidor remoto
    4. Configura las opciones SSH para evitar verificaciones de host
    
    Args:
        hostname (str): IP o nombre de dominio del servidor remoto
        username (str): Usuario SSH del servidor remoto
        password (str): Contraseña SSH del usuario
        port (int): Puerto SSH del servidor remoto (por defecto 22)
        
    Returns:
        bool: True si la clave fue copiada exitosamente, False en caso de error
        
    Raises:
        ValueError: Si algún parámetro requerido está vacío
    """
    
    # Validar parámetros de entrada
    if not hostname or not hostname.strip():
        logger.error("Hostname no puede estar vacío")
        raise ValueError("Hostname es requerido")
    
    if not username or not username.strip():
        logger.error("Username no puede estar vacío")
        raise ValueError("Username es requerido")
    
    if not password or not password.strip():
        logger.error("Password no puede estar vacío")
        raise ValueError("Password es requerido")
    
    if not isinstance(port, int) or port < 1 or port > 65535:
        logger.error(f"Puerto inválido: {port}")
        raise ValueError("Puerto debe ser un entero entre 1 y 65535")
    
    # Limpiar parámetros
    hostname = hostname.strip()
    username = username.strip()
    password = password.strip()
    
    logger.info(f"Iniciando configuración de clave SSH para {username}@{hostname}:{port}")
    
    try:
        # Paso 1: Verificar y crear directorio .ssh si no existe
        ssh_dir = Path("/root/.ssh")
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        logger.debug(f"Directorio SSH asegurado: {ssh_dir}")
        
        # Paso 2: Verificar si existe la clave privada
        private_key_path = ssh_dir / "id_rsa"
        public_key_path = ssh_dir / "id_rsa.pub"
        
        if not private_key_path.exists():
            logger.info("Clave SSH no encontrada, generando nuevo par de claves...")
            
            # Generar nuevo par de claves SSH RSA de 4096 bits
            keygen_cmd = [
                "ssh-keygen",
                "-t", "rsa",                    # Tipo de clave: RSA
                "-b", "4096",                   # Tamaño de clave: 4096 bits
                "-f", str(private_key_path),    # Archivo de salida
                "-N", "",                       # Sin passphrase (vacía)
                "-C", f"cyberscope-forensic@{hostname}"  # Comentario identificativo
            ]
            
            logger.debug(f"Ejecutando: {' '.join(keygen_cmd[:-2])} [PASSPHRASE_HIDDEN]")
            
            result = subprocess.run(
                keygen_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"Error generando claves SSH: {result.stderr}")
                return False
            
            # Verificar que las claves se generaron correctamente
            if not private_key_path.exists() or not public_key_path.exists():
                logger.error("Las claves SSH no se generaron correctamente")
                return False
            
            # Establecer permisos correctos para las claves
            private_key_path.chmod(0o600)  # Solo lectura/escritura para el propietario
            public_key_path.chmod(0o644)   # Lectura para todos, escritura para propietario
            
            logger.info("✅ Par de claves SSH generado exitosamente")
        else:
            logger.info("✅ Clave SSH existente encontrada")
        
        # Paso 3: Verificar que sshpass está disponible
        if not _check_sshpass_available():
            logger.error("sshpass no está disponible en el sistema")
            return False
        
        # Paso 4: Copiar clave pública al servidor remoto usando ssh-copy-id
        logger.info(f"Copiando clave pública a {username}@{hostname}:{port}...")
        
        # Construir comando ssh-copy-id con sshpass
        copy_id_cmd = [
            "sshpass", "-p", password,      # Usar sshpass con contraseña
            "ssh-copy-id",                  # Comando para copiar clave
            "-o", "StrictHostKeyChecking=no",        # No verificar host key
            "-o", "UserKnownHostsFile=/dev/null",    # No guardar host key
            "-o", "LogLevel=ERROR",                  # Solo mostrar errores
            "-o", f"ConnectTimeout=30",              # Timeout de conexión
            "-p", str(port),                         # Puerto SSH
            "-i", str(public_key_path),              # Archivo de clave pública
            f"{username}@{hostname}"                 # Usuario y host destino
        ]
        
        logger.debug(f"Ejecutando ssh-copy-id a {username}@{hostname}:{port}")
        
        result = subprocess.run(
            copy_id_cmd,
            capture_output=True,
            text=True,
            timeout=60  # Timeout más largo para la copia
        )
        
        if result.returncode == 0:
            logger.info("✅ Clave SSH copiada exitosamente al servidor remoto")
            
            # Paso 5: Verificar que la clave funciona haciendo un test de conexión
            if _test_ssh_key_connection(hostname, username, str(private_key_path), port):
                logger.info("✅ Verificación de clave SSH exitosa")
                return True
            else:
                logger.warning("⚠️ Clave copiada pero la verificación falló")
                return True  # Aún consideramos éxito si se copió
        else:
            logger.error(f"❌ Error copiando clave SSH: {result.stderr}")
            
            # Intentar diagnosticar el problema
            _diagnose_ssh_copy_error(result.stderr, hostname, port)
            return False
            
    except subprocess.TimeoutExpired as e:
        logger.error(f"⏰ Timeout durante operación SSH: {e}")
        return False
    except subprocess.CalledProcessError as e:
        logger.error(f"💥 Error en comando SSH: {e}")
        return False
    except Exception as e:
        logger.error(f"💥 Error inesperado: {e}")
        return False


def _check_sshpass_available() -> bool:
    """
    Verifica si sshpass está disponible en el sistema.
    
    Returns:
        bool: True si sshpass está disponible, False en caso contrario
    """
    try:
        result = subprocess.run(
            ["which", "sshpass"],
            capture_output=True,
            timeout=10
        )
        available = result.returncode == 0
        
        if available:
            logger.debug("✅ sshpass está disponible")
        else:
            logger.error("❌ sshpass NO está disponible")
            logger.error("Instala sshpass con: apt-get install sshpass")
            
        return available
    except Exception as e:
        logger.error(f"💥 Error verificando sshpass: {e}")
        return False


def _test_ssh_key_connection(hostname: str, username: str, private_key_path: str, port: int) -> bool:
    """
    Prueba la conexión SSH usando la clave privada generada.
    
    Args:
        hostname (str): Host remoto
        username (str): Usuario SSH
        private_key_path (str): Ruta a la clave privada
        port (int): Puerto SSH
        
    Returns:
        bool: True si la conexión es exitosa, False en caso contrario
    """
    try:
        logger.debug(f"🔍 Probando conexión SSH con clave a {username}@{hostname}:{port}")
        
        test_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=15",
            "-o", "BatchMode=yes",              # No solicitar contraseña
            "-o", "PasswordAuthentication=no",  # Solo usar clave
            "-i", private_key_path,             # Clave privada
            "-p", str(port),                    # Puerto
            f"{username}@{hostname}",           # Usuario@host
            "echo 'SSH_KEY_TEST_OK'"            # Comando de prueba
        ]
        
        result = subprocess.run(
            test_cmd,
            capture_output=True,
            text=True,
            timeout=20
        )
        
        if result.returncode == 0 and "SSH_KEY_TEST_OK" in result.stdout:
            logger.debug("✅ Test de conexión SSH con clave exitoso")
            return True
        else:
            logger.debug(f"⚠️ Test de conexión SSH falló: {result.stderr}")
            return False
            
    except Exception as e:
        logger.debug(f"💥 Error en test de conexión SSH: {e}")
        return False


def _diagnose_ssh_copy_error(error_message: str, hostname: str, port: int):
    """
    Diagnostica errores comunes en ssh-copy-id y proporciona sugerencias.
    
    Args:
        error_message (str): Mensaje de error de ssh-copy-id
        hostname (str): Host remoto
        port (int): Puerto SSH
    """
    error_lower = error_message.lower()
    
    logger.error("🔍 Diagnóstico de error SSH:")
    
    if "permission denied" in error_lower:
        logger.error("  - Credenciales incorrectas o usuario sin permisos SSH")
        logger.error("  - Verificar usuario y contraseña")
        
    elif "connection refused" in error_lower:
        logger.error(f"  - Servidor SSH no accesible en {hostname}:{port}")
        logger.error("  - Verificar que el servicio SSH esté corriendo")
        logger.error("  - Comprobar firewall y conectividad de red")
        
    elif "timeout" in error_lower or "timed out" in error_lower:
        logger.error(f"  - Timeout conectando a {hostname}:{port}")
        logger.error("  - Verificar conectividad de red")
        logger.error("  - El servidor puede estar sobrecargado")
        
    elif "host key verification failed" in error_lower:
        logger.error("  - Problema con verificación de host key")
        logger.error("  - Esto no debería ocurrir con nuestras opciones SSH")
        
    elif "no route to host" in error_lower:
        logger.error(f"  - No hay ruta de red a {hostname}")
        logger.error("  - Verificar conectividad de red y routing")
        
    else:
        logger.error(f"  - Error no reconocido: {error_message}")
        
    # Sugerencias generales
    logger.error("💡 Sugerencias:")
    logger.error(f"  - Probar conexión manual: ssh {hostname} -p {port}")
    logger.error("  - Verificar que el usuario tenga permisos SSH")
    logger.error("  - Comprobar configuración del servidor SSH")


def get_ssh_public_key() -> str:
    """
    Obtiene el contenido de la clave pública SSH actual.
    
    Returns:
        str: Contenido de la clave pública o cadena vacía si no existe
    """
    try:
        public_key_path = Path("/root/.ssh/id_rsa.pub")
        
        if public_key_path.exists():
            with open(public_key_path, 'r') as f:
                return f.read().strip()
        else:
            logger.warning("Clave pública SSH no encontrada")
            return ""
            
    except Exception as e:
        logger.error(f"Error leyendo clave pública SSH: {e}")
        return ""


def remove_ssh_keys():
    """
    Elimina las claves SSH existentes (útil para regenerar).
    
    Returns:
        bool: True si se eliminaron exitosamente, False en caso contrario
    """
    try:
        ssh_dir = Path("/root/.ssh")
        private_key = ssh_dir / "id_rsa"
        public_key = ssh_dir / "id_rsa.pub"
        
        removed = False
        
        if private_key.exists():
            private_key.unlink()
            logger.info("Clave privada SSH eliminada")
            removed = True
            
        if public_key.exists():
            public_key.unlink()
            logger.info("Clave pública SSH eliminada")
            removed = True
            
        if removed:
            logger.info("✅ Claves SSH eliminadas exitosamente")
        else:
            logger.info("No había claves SSH para eliminar")
            
        return True
        
    except Exception as e:
        logger.error(f"Error eliminando claves SSH: {e}")
        return False


# Función de utilidad para testing
def test_ssh_key_manager():
    """
    Función de prueba para el gestor de claves SSH.
    NO usar en producción - solo para testing.
    """
    print("🧪 Iniciando test del gestor de claves SSH...")
    
    # Verificar directorio SSH
    ssh_dir = Path("/root/.ssh")
    print(f"📁 Directorio SSH: {ssh_dir} (existe: {ssh_dir.exists()})")
    
    # Verificar claves existentes
    private_key = ssh_dir / "id_rsa"
    public_key = ssh_dir / "id_rsa.pub"
    
    print(f"🔑 Clave privada: {private_key} (existe: {private_key.exists()})")
    print(f"🔓 Clave pública: {public_key} (existe: {public_key.exists()})")
    
    # Verificar sshpass
    sshpass_available = _check_sshpass_available()
    print(f"🔧 sshpass disponible: {sshpass_available}")
    
    if public_key.exists():
        pub_key_content = get_ssh_public_key()
        print(f"📄 Contenido clave pública: {pub_key_content[:50]}...")
    
    print("✅ Test completado")


if __name__ == "__main__":
    # Configurar logging para testing
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Ejecutar test si se llama directamente
    test_ssh_key_manager()