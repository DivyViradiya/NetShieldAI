import sqlite3
import os

def migrate():
    basedir = r'd:\NetShield\NetShieldAI'
    db_path = os.path.join(basedir, 'instance', 'users_db.sqlite3')
    
    if not os.path.exists(db_path):
        print(f"DB not found at {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute("ALTER TABLE scan_log ADD COLUMN origin VARCHAR(20) DEFAULT 'manual'")
        conn.commit()
        print("Successfully added 'origin' column to scan_log table.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("Column 'origin' already exists.")
        else:
            print(f"Migration error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
