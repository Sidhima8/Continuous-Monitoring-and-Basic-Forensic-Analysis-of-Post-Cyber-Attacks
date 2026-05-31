import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication


#Recommendation Engine
def generate_recommendations(stats):
    rec = []

    if stats["open_ports"] > 5:
        rec.append("HIGH RISK: Too many open ports detected.")
        rec.append("Close unnecessary ports using firewall rules.")
        rec.append("Disable unused services immediately.")

    elif stats["open_ports"] > 0:
        rec.append("MEDIUM RISK: Some ports are open.")
        rec.append("Perform vulnerability scanning on open ports.")
        rec.append("Apply latest security patches.")

    else:
        rec.append("LOW RISK: No open ports detected.")
        rec.append("System appears secure. Continue monitoring.")

    return "\n- " + "\n- ".join(rec)


#Email Sender with Attachment
def send_email(report_path, stats):

    sender = "your_email@gmail.com"
    password = "your_app_password"   #Use Gmail App Password
    receiver = "soc@email.com"

    recommendations = generate_recommendations(stats)

    #Email Body
    body = f"""
  SECURITY ALERT

Scan Summary:
- Open Ports: {stats['open_ports']}
- Safe Ports: {stats['safe_ports']}

Recommendations:
{recommendations}

Report is attached.

-- Automated SOC Monitoring System
"""

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = receiver
    msg["Subject"] = "Security Alert Report"

    msg.attach(MIMEText(body, "plain"))

    #Attach PDF
    try:
        with open(report_path, "rb") as file:
            attachment = MIMEApplication(file.read(), _subtype="pdf")
            attachment.add_header(
                "Content-Disposition",
                "attachment",
                filename="Security_Report.pdf"
            )
            msg.attach(attachment)
    except Exception as e:
        print("Attachment Error:", e)

    #Send Email
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
        server.quit()

        print("Email sent successfully")

    except Exception as e:
        print("Email failed:", e)