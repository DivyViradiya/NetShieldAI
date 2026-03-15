import sys
import os

# Ensure project root is in path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from run import app
from extensions import db
from models import User

def check_db():
    print("--- Inspecting Database ---")
    with app.app_context():
        # 1. Print Columns
        columns = [c.name for c in User.__table__.columns]
        print("\n[+] User Table Columns:")
        for col in columns:
            print(f"  - {col}")
            
        if 'is_onboarded' in columns:
            print("\n[SUCCESS] 'is_onboarded' column exists!")
        else:
            print("\n[ERROR] 'is_onboarded' column is MISSING.")

        # 2. Print Users
        users = User.query.all()
        print(f"\n[+] Total Users in DB: {len(users)}")
        for u in users:
            print(f"  - ID: {u.id} | User: {u.username} | Onboarded: {getattr(u, 'is_onboarded', 'N/A')}")

if __name__ == "__main__":
    check_db()
