from run import app
from extensions import db
from models import User

def init_database():
    with app.app_context():
        # 1. Create the tables (if they don't exist)
        db.create_all()
        print("Database tables created/verified.")

        # 2. Create an Admin User
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin123') # Set your desired admin password here
            db.session.add(admin)
            print("Admin user created (User: admin, Pass: admin123)")
        else:
            print("Admin user already exists.")

        # 3. Create a Regular User (for testing standard access)
        if not User.query.filter_by(username='testuser').first():
            user = User(username='testuser', is_admin=False)
            user.set_password('user123') # Set your desired user password here
            db.session.add(user)
            print("Test user created (User: testuser, Pass: user123)")
        else:
            print("Test user already exists.")

        # 4. Save changes
        db.session.commit()
        print("Database initialized successfully.")

if __name__ == "__main__":
    init_database()