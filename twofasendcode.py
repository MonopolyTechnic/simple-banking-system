import os
import smtplib
import random
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage

def sendcode(phone_number, phone_carrier):
    # Email configuration
    #smtp_server = 'smtp.zoho.com'  # Zoho SMTP server
    smtp_server = 'smtp.gmail.com'  # gmail SMTP server
    smtp_port = 587                 # Port for TLS
    #email_sender = 'monopolytechnic@zohomail.com'
    email_sender = 'monopolytechnic@gmail.com'
    email_password = 'vqdh iwfp cnwf iioh'  # app password

    sms_gateways = {
        "AT&T": "txt.att.net",
        "T-Mobile": "tmomail.net",
        "Verizon": "vtext.com",
        "Sprint": "sprintpcs.com",
        
        # Regional Carriers
        "Cricket": "mms.cricketwireless.net",
        "Boost Mobile": "myboostmobile.com",
        "MetroPCS": "mymetropcs.com",
        "US Cellular": "email.uscc.net",
        "Page Plus Cellular": "vtext.com",  # Uses Verizon's gateway
        "TracFone": "mmst5.tracfone.com",
        
        # International Carriers
        "Rogers (Canada)": "txt.bell.ca",
        "Bell (Canada)": "txt.bell.ca",
        "Telus (Canada)": "msg.telus.com",
        
        # UK Carriers
        "Vodafone (UK)": "vodafone.net",
        "O2 (UK)": "o2.co.uk",
        "Orange (UK)": "orange.net",
        
        # Other International Carriers
        "Telenor (Norway)": "telenor.no",
        "Telia (Sweden)": "telia.se",
    }


    # Recipient phone number and carrier (change based on the recipient's carrier)
    recipient_number = phone_number  # The recipient's phone number

    if (phone_carrier in sms_gateways.keys()):
        carrier_gateway = sms_gateways[phone_carrier]
    else:
        return

    #carrier_gateway = 'tmomail.net'   # T-Mobile carrier gateway
    recipient_sms = f'{recipient_number}@{carrier_gateway}'
    #recipient_sms = '+19292787789@mms.us.lycamobile.com'

    # Generate a random 6-digit verification code
    verification_code = random.randint(100000, 999999)

    subject = 'Your Verification Code'
    body = f'Your verification code is: {verification_code}'

    message = MIMEMultipart()
    message['From'] = email_sender
    message['To'] = recipient_sms
    message['Subject'] = subject

    image_path = 'C:/Users/bachia/Pictures/piggybank.jpg'  # Replace with the path to your image
    message.attach(MIMEText(body, 'plain'))

    with open(image_path, 'rb') as img_file:
        img = MIMEImage(img_file.read())
        img.add_header('Content-Disposition', 'attachment', filename=os.path.basename(image_path))
        message.attach(img)

    # Send the SMS via email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Upgrade the connection to secure
        server.login(email_sender, email_password)
        server.sendmail(email_sender, recipient_sms, message.as_string())
    # Ask for user input to verify
    print(verification_code)


if __name__ == "__main__":
    sendcode(sys.argv[1], sys.argv[2])