import os.path
import base64
from email.message import EmailMessage
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def authenticate_gmail():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
            
    return build('gmail', 'v1', credentials=creds)

def send_otp_email(recipient_email, otp_code):
    """Drafts and sends the OTP email via Gmail API."""
    try:
        service = authenticate_gmail()
        
        message = EmailMessage()
        message.set_content(f"Hello,\n\nYour NetShieldAI password reset OTP is: {otp_code}\n\nIf you did not request this, please ignore this email.")
        message['To'] = recipient_email
        message['From'] = 'admin.netshieldai@gmail.com'
        message['Subject'] = 'Your NetShieldAI Password Reset OTP'

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
    test_user_email = "your_test_user@gmail.com" 
    sample_otp = "123456"
    
    print("Starting Gmail OTP Authentication Flow...")
    send_otp_email(test_user_email, sample_otp)
