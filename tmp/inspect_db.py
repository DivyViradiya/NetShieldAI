import sqlite3
import os

db_path = r"d:\NetShield\NetShieldAI\instance\users_db.sqlite3"
output_path = r"d:\NetShield\NetShieldAI\tmp\inspect_output.txt"

if not os.path.exists(db_path):
    with open(output_path, 'w') as f:
        f.write(f"Error: Database not found at {db_path}")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    with open(output_path, 'w') as f:
        # Get tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        f.write(f"Tables: {tables}\n")

        for (table_name,) in tables:
            f.write(f"\n--- {table_name} ---\n")
            # Get columns
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            f.write("Columns:\n")
            for col in columns:
                f.write(f"  {col[1]} ({col[2]})\n")
            
            # Get sample data
            cursor.execute(f"SELECT * FROM {table_name} LIMIT 3;")
            rows = cursor.fetchall()
            f.write("Sample Rows:\n")
            for row in rows:
                f.write(f"  {row}\n")

except Exception as e:
    with open(output_path, 'w') as f:
        f.write(f"Error: {e}")
finally:
    conn.close()
    print("Inspection complete.")
