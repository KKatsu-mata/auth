from fastapi import APIRouter, HTTPException
from app.schemas import UserCreate
from app.database import get_connection
import bcrypt

router = APIRouter()

@router.post("/register")
def register(user: UserCreate):
    # 1. DB接続
    conn = get_connection()
    cur = conn.cursor()

    # 2. usernameの重複チェック
    SEARCH_USERNAME = """
    SELECT username FROM users WHERE username = %s;
    """
    cur.execute(SEARCH_USERNAME, (user.username,))
    if cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="そのユーザーネームはすでに存在します")

    # 3. パスワードのハッシュ化
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode("utf-8")

    # 4. INSERT
    CREATE_USER = """
    INSERT INTO users (username, hashed_password) VALUES (%s, %s);
    """
    cur.execute(CREATE_USER, (user.username, hashed_password,))
    conn.commit()

    # 5. 接続終了
    cur.close()
    conn.close()
    return {"message": "ユーザ登録が完了しました!"}

@router.post("/login")
def login(user: UserCreate):
    # 1. DB接続
    conn = get_connection()
    cur = conn.cursor()

    # 2. ユーザー情報照会
    SELECT_HASHED_PASSWORD = """
    SELECT hashed_password FROM users WHERE username = %s;
    """
    cur.execute(SELECT_HASHED_PASSWORD, (user.username,))
    result = cur.fetchone()
    if result is None:
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="ユーザーネームまたはパスワードが間違っています")

    is_valid = bcrypt.checkpw(user.password.encode('utf-8'), result[0].encode('utf-8'))
    if not is_valid:
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="ユーザーネームまたはパスワードが間違っています")
    
    # 4. 接続終了
    cur.close()
    conn.close()
    return {"message": "ログイン成功しました"}
