from app.database import get_connection

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY NOT NULL, 
    username VARCHAR(50) UNIQUE NOT NULL, 
    hashed_password TEXT NOT NULL, 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);"""

def create_tables():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(CREATE_USERS_TABLE)
    conn.commit()
    cur.close()
    conn.close()

if __name__ == "__main__":
    create_tables()
    print("テーブル作成完了")
