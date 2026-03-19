import smtplib

s = smtplib.SMTP("localhost", 2525)
s.ehlo()
s.starttls()
s.ehlo()

s.sendmail(
    "alice@test.com",
    ["bob@test.com"],
    "Subject: Hello\n\nTest message"
)
s.quit()