import os
from .utils import FINDINGS, logger

def whois_lookup(domain: str):
    """
    Ejecuta una consulta WHOIS sobre un dominio y registra los primeros datos útiles.
    """
    try:
        res = os.popen(f"whois {domain}").read()
        if res:
            FINDINGS.append(f"[WHOIS] Resultado WHOIS para {domain}:\n{res[:500]}")
        else:
            FINDINGS.append(f"[WHOIS] No se obtuvo información WHOIS para {domain}")
    except Exception as e:
        logger.error(f"WHOIS falló para {domain}: {e}")
        FINDINGS.append(f"[ERROR] WHOIS falló: {e}")


def ip_lookup(ip: str):
    """
    Realiza búsqueda RDAP (IPWhois) para una IP.
    """
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        res = obj.lookup_rdap()

        FINDINGS.append(f"[IPINFO] Información sobre {ip}:")
        FINDINGS.append(f"[IPINFO] ASN: {res.get('asn')}")
        FINDINGS.append(f"[IPINFO] Organización: {res.get('network', {}).get('name')}")
        FINDINGS.append(f"[IPINFO] País: {res.get('network', {}).get('country')}")

    except ImportError:
        msg = "ipwhois no está instalado. Ejecuta: pip install ipwhois"
        logger.error(msg)
        FINDINGS.append(f"[ERROR] {msg}")

    except Exception as e:
        logger.error(f"IP Lookup falló para {ip}: {e}")
        FINDINGS.append(f"[ERROR] IP Lookup falló: {e}")
