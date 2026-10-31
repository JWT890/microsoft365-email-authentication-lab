import smtplib
from getpass import getpass
from email.message import EmailMessage

SENDER = "alice@jon-maillab.org"          # verified single sender

user     = input("SMTP2GO SMTP username: ")
password = getpass("SMTP2GO SMTP password (hidden): ")
my_gmail = input("Your own Gmail address: ")
TARGETS  = [my_gmail, "bob@jon-maillab.org"]   # your own mailboxes only

msg = EmailMessage()
msg["From"] = f"Alice <{SENDER}>"
msg["To"] = ", ".join(TARGETS)
msg["Subject"] = "Unauthorized sender test 3 (reject)"
msg.set_content("Lab test: my own domain, sent through a third-party relay not in my SPF/DKIM.")

with smtplib.SMTP("mail.smtp2go.com", 587, timeout=30) as s:
    s.set_debuglevel(1)
    s.starttls()
    s.login(user, password)
    s.send_message(msg, from_addr=SENDER, to_addrs=TARGETS)