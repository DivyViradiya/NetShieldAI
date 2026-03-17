"""
One-time migration: Fix stale scan_profile schema.
Recreates all scheduler tables via SQLite (no app import needed).
"""
import sqlite3
import os

db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'scheduler_db.sqlite3')
conn = sqlite3.connect(db_path)
c = conn.cursor()

print("Current scan_profile schema:")
c.execute("PRAGMA table_info(scan_profile)")
for col in c.fetchall():
    print(" ", col)

# Recreate scan_profile table without the stale 'config' column
print("\nMigrating scan_profile table...")
c.executescript("""
    PRAGMA foreign_keys=OFF;

    BEGIN TRANSACTION;

    CREATE TABLE IF NOT EXISTS scan_profile_new (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        name VARCHAR(150) NOT NULL,
        description TEXT,
        is_active BOOLEAN DEFAULT 1,
        created_at DATETIME,
        updated_at DATETIME
    );

    INSERT INTO scan_profile_new (id, user_id, name, description, is_active, created_at, updated_at)
    SELECT id, user_id, name, description, is_active, created_at, updated_at
    FROM scan_profile;

    DROP TABLE scan_profile;
    ALTER TABLE scan_profile_new RENAME TO scan_profile;

    COMMIT;

    PRAGMA foreign_keys=ON;
""")

conn.commit()
conn.close()

print("Done! scan_profile table migrated successfully.")
print("\nNew schema:")
conn2 = sqlite3.connect(db_path)
c2 = conn2.cursor()
c2.execute("PRAGMA table_info(scan_profile)")
for col in c2.fetchall():
    print(" ", col)
conn2.close()
