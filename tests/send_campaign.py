import json
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path

CAMPAIGN_PATH = Path("campaign.json")

# ====== CONFIG SMTP (à adapter) ======
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

SMTP_USER = "reoula95@gmail.com"        # <-- change
SMTP_APP_PASSWORD = "jpoqpousqadsvpbk"         # <-- change

TO_EMAIL = "antiphisher.ai@gmail.com"

DELAY_SECONDS = 30  # anti-spam: évite d'envoyer 15 mails d'un coup

def send_one(mail: dict):
    msg = EmailMessage()
    msg["To"] = TO_EMAIL

    # IMPORTANT:
    # "From" affiché peut être différent, mais Gmail alignera souvent avec SMTP_USER.
    # On met quand même les headers pour tester la détection côté contenu.
    msg["From"] = f'{mail["from_name"]} <{mail["from_email"]}>'
    msg["Subject"] = mail["subject"]

    # multipart text+html
    msg.set_content(mail["body_text"])
    msg.add_alternative(mail["body_html"], subtype="html")

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.ehlo()
        s.starttls()
        s.login(SMTP_USER, SMTP_APP_PASSWORD)
        s.send_message(msg)

def main():
    if not CAMPAIGN_PATH.exists():
        raise FileNotFoundError(f"Missing {CAMPAIGN_PATH}. Create it with the JSON I gave you.")

    campaign = json.loads(CAMPAIGN_PATH.read_text(encoding="utf-8"))

    print(f"Sending {len(campaign)} emails to {TO_EMAIL} ...")
    for i, mail in enumerate(campaign, 1):
        send_one(mail)
        print(f"[{i}/{len(campaign)}] sent: {mail['id']} ({mail['kind']}) - {mail['subject']}")
        time.sleep(DELAY_SECONDS)

    print("Done.")

if __name__ == "__main__":
    main()