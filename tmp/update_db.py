import sqlite3
import os

db_path = r"d:\NetShield\NetShieldAI\instance\users_db.sqlite3"
output_path = r"d:\NetShield\NetShieldAI\tmp\update_output.txt"

if not os.path.exists(db_path):
    with open(output_path, 'w') as f:
        f.write(f"Error: Database not found at {db_path}")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    with open(output_path, 'w') as f:
        # Count BEFORE
        cursor.execute("SELECT COUNT(*) FROM user WHERE is_email_verified = 0;")
        unverified_before = cursor.fetchone()[0]
        f.write(f"Unverified users BEFORE: {unverified_before}\n")

        # Update
        cursor.execute("UPDATE user SET is_email_verified = 1;")
        affected_rows = cursor.rowcount
        conn.commit()
        f.write(f"Affected rows: {affected_rows}\n")

        # Count AFTER
        cursor.execute("SELECT COUNT(*) FROM user WHERE is_email_verified = 0;")
        unverified_after = cursor.fetchone()[0]
        f.write(f"Unverified users AFTER: {unverified_after}\n")
        
        if unverified_after == 0:
             f.write("Verification successful!\n")
        else:
             f.write("WARNING: Some users are still unverified!\n")

except Exception as e:
    with open(output_path, 'w') as f:
        f.write(f"Error: {e}")
finally:
    conn.close()
    print("Update complete.")
