from app.database import get_connection

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY NOT NULL, 
    username VARCHAR(50) UNIQUE, 
    hashed_password TEXT, 
    google_sub VARCHAR(255) UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);"""

MIGRATE_V2 = """
    ALTER TABLE users ALTER COLUMN username DROP NOT NULL;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub VARCHAR(255) UNIQUE;
    ALTER TABLE users ALTER COLUMN hashed_password DROP NOT NULL;
"""

def create_tables():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(CREATE_USERS_TABLE)
    conn.commit()
    cur.close()
    conn.close()

def migrate():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(MIGRATE_V2)
    conn.commit()
    cur.close()
    conn.close()

if __name__ == "__main__":
    create_tables()
    print("テーブル作成完了")
