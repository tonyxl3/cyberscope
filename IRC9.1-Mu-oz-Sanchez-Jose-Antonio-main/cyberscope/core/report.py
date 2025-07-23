import json
from datetime import datetime

from .utils import FINDINGS, logger

# ReportLab para PDF
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab no está disponible. Reportes PDF deshabilitados.")


def exportar_json(nombre: str = "hallazgos_forenses.json") -> bool:
    """
    Exporta los hallazgos encontrados a un archivo JSON.
    """
    try:
        data = {
            "timestamp": datetime.now().isoformat(),
            "version": "CyberScope v2.0",
            "total_findings": len(FINDINGS),
            "findings": FINDINGS
        }

        with open(nombre, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Hallazgos exportados a JSON: {nombre}")
        return True

    except Exception as e:
        logger.error(f"Error exportando a JSON: {e}")
        return False


def generar_reporte_pdf(nombre: str = "reporte_forense.pdf") -> bool:
    """
    Genera un reporte PDF con todos los hallazgos clasificados por categoría.
    """
    if not REPORTLAB_AVAILABLE:
        logger.error("ReportLab no está disponible para generar PDF")
        return False

    try:
        c = canvas.Canvas(nombre, pagesize=letter)
        width, height = letter

        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, height - 50, "CyberScope - Reporte Forense")

        c.setFont("Helvetica", 12)
        c.drawString(40, height - 80, f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(40, height - 100, "Generado por: CyberScope v2.0")
        c.drawString(40, height - 120, f"Total de hallazgos: {len(FINDINGS)}")
        c.line(40, height - 140, width - 40, height - 140)

        y = height - 170
        current_section = None

        for finding in FINDINGS:
            if y < 60:
                c.showPage()
                y = height - 50

            if "]" in finding:
                section = finding.split("]")[0][1:]
                if section != current_section:
                    y -= 10
                    c.setFont("Helvetica-Bold", 12)
                    c.setFillColor(colors.darkblue)
                    c.drawString(40, y, f"=== {section} ===")
                    y -= 20
                    current_section = section
                    c.setFillColor(colors.black)

            c.setFont("Helvetica", 10)

            # Dividir líneas largas
            if len(finding) > 100:
                words = finding.split()
                line = ""
                for word in words:
                    test_line = f"{line} {word}" if line else word
                    if len(test_line) > 100:
                        c.drawString(50, y, line)
                        y -= 15
                        line = word
                    else:
                        line = test_line
                if line:
                    c.drawString(50, y, line)
                    y -= 15
            else:
                c.drawString(50, y, finding)
                y -= 15

        c.save()
        logger.info(f"Reporte PDF generado: {nombre}")
        return True

    except Exception as e:
        logger.error(f"No se pudo generar el reporte PDF: {e}")
        return False

