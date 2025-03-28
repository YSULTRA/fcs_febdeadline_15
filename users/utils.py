import smtplib
from email.message import EmailMessage
from django.core.mail import send_mail
from django.conf import settings



def send_email_otp(email, otp):
    """Send OTP via Email"""
    subject = "Your Email Verification OTP"
    message = f"Your OTP for email verification is: {otp}"
    email_from = settings.DEFAULT_FROM_EMAIL  # Use your Django email settings
    send_mail(subject, message, email_from, [email])

def send_sms_otp(email, mobile, otp, carrier):
    """For testing: Send mobile OTP to email instead of actual SMS"""
    subject = "Your Mobile OTP (Sent via Email for Testing)"
    message = f"Your OTP for mobile verification (originally for {mobile}) is: {otp}"

    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
        print(f"✅ OTP sent to email ({email}) instead of SMS for testing")
        return {"otp": otp, "message": "OTP sent to email instead of mobile"}
    except Exception as e:
        print(f"❌ Error sending OTP via email: {e}")
        return {"error": str(e)}



# def send_sms_otp(mobile, otp, carrier):
#     CARRIER_GATEWAYS = {
#         'att': '@txt.att.net',      # SMS Gateway (not MMS)
#         'tmobile': '@tmomail.net',
#         'verizon': '@vtext.com',
#         'sprint': '@messaging.sprintpcs.com'
#     }

#     if carrier not in CARRIER_GATEWAYS:
#         return {"error": "Unsupported carrier"}

#     to_number = f"{mobile}{CARRIER_GATEWAYS[carrier]}"

#     subject = "OTP Verification"
#     message = f"Your OTP is: {otp}. Do not share it."

#     try:
#         print(f"📨 Sending OTP to {to_number}...")

#         msg = EmailMessage()
#         msg.set_content(message)  # Plain text only
#         msg["Subject"] = subject
#         msg["From"] = settings.EMAIL_HOST_USER
#         msg["To"] = to_number

#         with smtplib.SMTP("smtp.gmail.com", 587) as server:
#             server.starttls()
#             server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
#             server.send_message(msg)

#         print(f"✅ OTP sent successfully to {to_number}")
#         return {"otp": otp, "message": "OTP sent successfully"}

#     except Exception as e:
#         print(f"❌ Error sending SMS: {e}")
#         return {"error": str(e)}