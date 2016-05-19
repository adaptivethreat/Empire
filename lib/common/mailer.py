import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.MIMEBase import MIMEBase
from email import encoders

from datetime import datetime

ENABLED = False


def notify(body="Agent connected"):
    fromaddr = ""
    toaddr = fromaddr

    msg = MIMEMultipart()

    msg['From'] = fromaddr
    msg['To'] = toaddr

    now = datetime.now().strftime("%Y-%m-%d");

    msg['Subject'] = "RT notification : "+now


    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('SMTP_SERVER_ADDR', 'SMTP_PORT')
    server.starttls()
    server.login(fromaddr, "password")
    text = msg.as_string()
    server.sendmail(fromaddr, toaddr, text)
    server.quit()
