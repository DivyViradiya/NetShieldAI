import os
import sys

# Ensure the project root is in the path for imports
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

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

        # 2. Create an Admin User
        if not User.query.filter_by(username='Admin').first():
            admin = User(username='Admin', email='admin.netshieldai@gmail.com', is_admin=True)
            # [SECURITY] Use a placeholder that MUST be changed
            admin.set_password('Dv@020904') 
            db.session.add(admin)
            print("Admin user created (User: Admin, Pass: Dv@020904)")
            print("IMPORTANT: Change this password immediately after first login!")
        else:
            print("Admin user already exists.")


        # 4. Save changes
        db.session.commit()
        print("Database initialized successfully.")

if __name__ == "__main__":
    init_database()