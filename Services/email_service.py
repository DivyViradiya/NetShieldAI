import os.path
import base64
from email.message import EmailMessage
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

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
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
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
            
            # If we have a logo and it's referenced in HTML as cid:logo_img
            if logo_path and os.path.exists(logo_path):
                # We need to add the related image to the HTML part
                # EmailMessage makes this a bit tricky with add_alternative.
                # A better way for CID with EmailMessage:
                import mimetypes
                maintype, subtype = mimetypes.guess_type(logo_path)[0].split('/')
                with open(logo_path, 'rb') as img:
                    message.get_payload()[1].add_related(
                        img.read(), 
                        maintype=maintype, 
                        subtype=subtype, 
                        cid='logo_img'
                    )

        # The API requires the email to be base64 encoded
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {'raw': encoded_message}

        # Send the email
        send_message = service.users().messages().send(userId="me", body=create_message).execute()
        print(f"Success! Message Id: {send_message['id']}")
        return True
        
    except Exception as error:
        print(f"An error occurred: {error}")
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
