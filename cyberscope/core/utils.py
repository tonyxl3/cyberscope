import logging

# Lista global de hallazgos (centralizada)
FINDINGS = []

# Configuración del logger global
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cyberscope.log", mode="a"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("cyberscope")

