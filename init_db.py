import os
import sys
from dotenv import load_dotenv

# Ensure the project root is in the path for imports
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Load environment variables
load_dotenv(os.path.join(PROJECT_ROOT, '.env'))

try:
    from run import app
    from extensions import db
    from models import User
except ImportError as e:
    print(f"Error importing app components: {e}")
    print(f"Current sys.path: {sys.path}")
    sys.exit(1)

def init_database():
    with app.app_context():
        # 1. Create the tables (if they don't exist)
        db.create_all()
        print("Database tables created/verified.")

        # 2. Read Admin credentials from Environment (or use defaults)
        admin_username = os.environ.get('ADMIN_USERNAME', 'Admin')
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin.netshieldai@gmail.com')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'ChangeMe123!')

        # 3. Create an Admin User
        existing_user = User.query.filter(
            (User.username == admin_username) | (User.email == admin_email)
        ).first()

        if not existing_user:
            admin = User(username=admin_username, email=admin_email, is_admin=True)
            admin.set_password(admin_password) 
            db.session.add(admin)
            print(f"Admin user created (User: {admin_username}, Email: {admin_email})")
            if admin_password == 'ChangeMe123!':
                print("WARNING: Using default admin password. Change this immediately!")
        else:
            print(f"User with username '{admin_username}' or email '{admin_email}' already exists.")
            if not existing_user.is_admin:
                print(f"User '{admin_username}' exists but is not an admin. Promoting to admin...")
                existing_user.is_admin = True

        # 4. Save changes
        db.session.commit()
        print("Database initialized successfully.")

if __name__ == "__main__":
    init_database()