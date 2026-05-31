import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

def open_db():
    """DB接続用の関数
    arg:
        None
    return:
        conn: DB接続オブジェクト
        cur: DBカーソルオブジェクト
    """
    conn =get_connection()
    cur = conn.cursor()
    return conn, cur

def close_db(conn, cur):
    """DB切断用の関数
    arg:
        conn: DB接続オブジェクト
        cur: DBカーソルオブジェクト
    return:
        None
    """
    cur.close()
    conn.close()
    