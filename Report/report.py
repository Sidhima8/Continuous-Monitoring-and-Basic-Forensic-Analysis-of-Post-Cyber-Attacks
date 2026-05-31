import os
import shutil
import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


def generate_report(network_data, system_info, host_info, recommendations):

    #Save in reports folder
    reports_dir = "reports"

    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    #Unique file name
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(reports_dir, f"security_report_{timestamp}.pdf")

    #Create PDF
    doc = SimpleDocTemplate(file_path)
    styles = getSampleStyleSheet()
    content = []

    #Title
    content.append(Paragraph("SOC Incident & Forensic Analysis Report", styles["Title"]))
    content.append(Spacer(1, 12))

    #Time
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content.append(Paragraph(f"Generated At: {now}", styles["Normal"]))
    content.append(Spacer(1, 10))

    #Data
    open_ports = network_data.get("open_ports", 0)
    safe_ports = network_data.get("safe_ports", 0)
    suspicious_services = network_data.get("suspicious_services", [])

    severity = "LOW"
    if open_ports > 5:
        severity = "MEDIUM"
    if suspicious_services:
        severity = "HIGH"

    content.append(Paragraph(f"Severity Level: {severity}", styles["Normal"]))
    content.append(Paragraph(f"Open Ports: {open_ports}", styles["Normal"]))
    content.append(Paragraph(f"Safe Ports: {safe_ports}", styles["Normal"]))
    content.append(Spacer(1, 10))

    #IOC
    content.append(Paragraph("Indicators of Compromise", styles["Heading2"]))
    content.append(Spacer(1, 5))

    if suspicious_services:
        for service in suspicious_services:
            content.append(Paragraph(f"Suspicious: {service}", styles["Normal"]))
    else:
        content.append(Paragraph("No major IOC detected", styles["Normal"]))

    content.append(Spacer(1, 10))

    #System Info
    content.append(Paragraph("System Info", styles["Heading2"]))
    content.append(Spacer(1, 5))
    content.append(Paragraph(str(system_info).replace("\n", "<br/>"), styles["Normal"]))
    content.append(Spacer(1, 10))

    #Host Scan
    content.append(Paragraph("Host Scan", styles["Heading2"]))
    content.append(Spacer(1, 5))
    content.append(Paragraph(str(host_info)[:1000].replace("\n", "<br/>"), styles["Normal"]))
    content.append(Spacer(1, 10))

    #Recommendations
    content.append(Paragraph("Recommendations", styles["Heading2"]))
    content.append(Spacer(1, 5))

    for rec in str(recommendations).split("\n"):
        if rec.strip():
            content.append(Paragraph(rec, styles["Normal"]))

    #Build PDF
    doc.build(content)

    #Update latest report
    latest_path = os.path.join(reports_dir, "security_report_latest.pdf")
    shutil.copy(file_path, latest_path)

    print(f"[INFO] Report generated: {file_path}")
    print(f"[INFO] Latest report updated: {latest_path}")

    return file_path
