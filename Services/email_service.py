import os.path
import base64
from email.message import EmailMessage
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from core.logger_setup import logger

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# --- [FIX] Persistent Paths for Redirected Directory Structure ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN_PATH = os.path.join(PROJECT_ROOT, 'config', 'token.json')
CREDENTIALS_PATH = os.path.join(PROJECT_ROOT, 'config', 'credentials.json')

def authenticate_gmail():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first time.
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    
    # If there are no (valid) credentials available, let the user log in.
    import google.auth.exceptions
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except google.auth.exceptions.RefreshError:
                logger.warning("[!] [EMAIL] Token refresh failed (invalid_grant).")
                if __name__ == '__main__':
                    logger.info("[*] [EMAIL] Forcing re-authentication...")
                    if os.path.exists(TOKEN_PATH): os.remove(TOKEN_PATH)
                    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
                    creds = flow.run_local_server(port=0)
                else:
                    logger.error("[!] [EMAIL] Gmail API Token expired and cannot be refreshed automatically. Run 'python Services/email_service.py' manually as administrator.")
                    return None
        else:
            if __name__ == '__main__':
                flow = InstalledAppFlow.from_client_secrets_file(
                    CREDENTIALS_PATH, SCOPES)
                creds = flow.run_local_server(port=0)
            else:
                logger.error("[!] [EMAIL] Gmail API Token missing. Run 'python Services/email_service.py' manually as administrator.")
                return None
        # Save the credentials for the next run
        with open(TOKEN_PATH, 'w') as token:
            token.write(creds.to_json())
            
    return build('gmail', 'v1', credentials=creds)

def send_otp_email(recipient_email, otp_code, html_content=None, logo_path=None):
    """Drafts and sends the OTP email via Gmail API."""
    try:
        service = authenticate_gmail()
        
        message = EmailMessage()
        message['To'] = recipient_email
        message['From'] = 'admin.netshieldai@gmail.com'
        message['Subject'] = 'Your NetShieldAI Password Reset OTP'

        # Plain text fallback
        plain_text = f"Hello,\n\nYour NetShieldAI password reset OTP is: {otp_code}\n\nIf you did not request this, please ignore this email."
        message.set_content(plain_text)

        # HTML Content
        if html_content:
            message.add_alternative(html_content, subtype='html')
            # [CID Logo Fix]
            logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NS_Logo.png')
            if os.path.exists(logo_path):
                try:
                    html_part = message.get_payload()[1]
                    with open(logo_path, 'rb') as f:
                        html_part.add_related(f.read(), 'image', 'png', cid='<logo>')
                except Exception as e:
                    logger.warning(f"[!] [EMAIL] Failed to attach logo CID: {e}")

        # The API requires the email to be base64 encoded
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {'raw': encoded_message}

        # Send the email
        send_message = service.users().messages().send(userId="me", body=create_message).execute()
        logger.info(f"[+] [EMAIL] OTP email sent successfully. Message Id: {send_message['id']}")
        return True
        
    except Exception as error:
        logger.error(f"[!] [EMAIL] Error sending OTP email: {error}")
        return False

def send_consent_email(recipient_email, target_url, profile_name, confirm_url, html_content=None, logo_path=None):
    """Sends a scan authorization request email."""
    try:
        service = authenticate_gmail()
        
        message = EmailMessage()
        message['To'] = recipient_email
        message['From'] = 'admin.netshieldai@gmail.com'
        message['Subject'] = f'CONSENT REQUIRED: Security Scan for {target_url}'

        # Plain text fallback
        plain_text = (
            f"Authorization Required for Security Scan\n\n"
            f"A security scan has been scheduled for your asset: {target_url}\n"
            f"Profile: {profile_name}\n\n"
            f"To authorize this scan, please visit: {confirm_url}\n\n"
            f"This link is valid for 1 hour."
        )
        message.set_content(plain_text)

        if html_content:
            message.add_alternative(html_content, subtype='html')
            # [CID Logo Fix]
            logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NS_Logo.png')
            if os.path.exists(logo_path):
                try:
                    html_part = message.get_payload()[1]
                    with open(logo_path, 'rb') as f:
                        html_part.add_related(f.read(), 'image', 'png', cid='<logo>')
                except Exception as e:
                    logger.warning(f"[!] [EMAIL] Failed to attach logo CID: {e}")

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {'raw': encoded_message}
        send_message = service.users().messages().send(userId="me", body=create_message).execute()
        logger.info(f"[+] [EMAIL] Consent email sent successfully. Message Id: {send_message['id']}")
        return True
    except Exception as error:
        logger.error(f"[!] [EMAIL] Error sending consent email: {error}")
        return False

def send_report_link_email(recipient_email, links_info, profile_name, html_content=None):
    """Sends secure scan report download links to a recipient."""
    try:
        service = authenticate_gmail()
        
        message = EmailMessage()
        message['To'] = recipient_email
        message['From'] = 'admin.netshieldai@gmail.com'
        message['Subject'] = f'SECURE REPORT: {profile_name} Scan Completed'

        # Build plain text content
        body = f"Hello,\n\nThe scheduled scan for profile '{profile_name}' has completed.\n\n"
        body += "You can access your secure reports via the links below (Valid for 48 hours):\n\n"
        for item in links_info:
             body += f"- {item['tool']} for {item['target']}:\n  Link: {item['url']}\n  Expires: {item['expires_at']}\n\n"
        
        body += "These links are secure and track access for audit compliance.\n\nBest Regards,\nNetShield Team"
        message.set_content(body)

        if html_content:
            message.add_alternative(html_content, subtype='html')
            # [CID Logo Fix]
            logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NS_Logo.png')
            if os.path.exists(logo_path):
                try:
                    html_part = message.get_payload()[1]
                    with open(logo_path, 'rb') as f:
                        html_part.add_related(f.read(), 'image', 'png', cid='<logo>')
                except Exception as e:
                    logger.warning(f"[!] [EMAIL] Failed to attach logo CID: {e}")

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {'raw': encoded_message}
        send_message = service.users().messages().send(userId="me", body=create_message).execute()
        logger.info(f"[+] [EMAIL] Report delivery email sent to {recipient_email}. Message Id: {send_message['id']}")
        return True
    except Exception as error:
        logger.error(f"[!] [EMAIL] Error sending report delivery email: {error}")
        return False

# --- Test the function ---
if __name__ == '__main__':
    # Make sure this email is added to your 'Test Users' in the GCP Console!
    test_user_email = "admin.netshieldai@gmail.com" 
    sample_otp = "123456"
    
    print("Starting Gmail OTP Authentication Flow...")
    success = send_otp_email(test_user_email, sample_otp)
    if success:
        print("\n[SUCCESS] Gmail API is fully configured and test email sent!")
    else:
        print("\n[FAILURE] Gmail API configuration failed. Check the error above.")
