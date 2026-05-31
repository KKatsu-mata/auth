from fastapi import APIRouter, HTTPException, Response, Cookie, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials
import bcrypt
import uuid
import redis
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from app.schemas import UserCreate
import app.database as database

router = APIRouter()
r = redis.Redis(host='localhost', port=6379, decode_responses=True)
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
security = HTTPBearer()

@router.post("/register")
def register(user: UserCreate):
    # 1. DB接続
    conn, cur = database.open_db()

    # 2. usernameの重複チェック
    SEARCH_USERNAME = """
    SELECT username FROM users WHERE username = %s;
    """
    try:
        cur.execute(SEARCH_USERNAME, (user.username,))
        if cur.fetchone():
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
    finally:
        database.close_db(conn, cur)
    return {"message": "ユーザ登録が完了しました!"}

@router.post("/login")
def login(user: UserCreate, response: Response):
    # 1. DB接続
    conn, cur = database.open_db()

    # 2. ユーザー情報照会
    SELECT_HASHED_PASSWORD = """
    SELECT hashed_password FROM users WHERE username = %s;
    """
    try:
        cur.execute(SELECT_HASHED_PASSWORD, (user.username,))
        result = cur.fetchone()
        if result is None:
            raise HTTPException(status_code=400, detail="ユーザーネームまたはパスワードが間違っています")

        is_valid = verify_password(user.password, result[0])
        if not is_valid:
            raise HTTPException(status_code=400, detail="ユーザーネームまたはパスワードが間違っています")
    
    # 4. 接続終了
    finally:
        database.close_db(conn, cur)

    # 5. セッションID発行
    session_id = str(uuid.uuid4())
    r.setex(session_id, 1800, user.username)
    response.set_cookie(key="session_id", value=session_id)
    return {"message": "ログイン成功しました"}

@router.post("/login-jwt")
def login_jwt(user: UserCreate):
    # 1. DB接続
    conn, cur =database.open_db()

    # 2. ユーザ情報照会
    SELECT_HASHED_PASSWORD = """
        SELECT hashed_password FROM users WHERE username = %s;
    """
    try:
        cur.execute(SELECT_HASHED_PASSWORD, (user.username, ))
        result = cur.fetchone()
        if result is None:
            raise HTTPException(status_code=400, detail="ユーザーネームまたはパスワードが間違っています")
        is_valid = verify_password(user.password, result[0])
        if not is_valid:
            raise HTTPException(status_code=400, detail="ユーザーネームまたはパスワードが間違っています")
    finally:
        database.close_db(conn, cur)
    
    # 3. JWTトークン発行
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": user.username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me")
def me(session_id: str = Cookie(default=None)):
    if session_id is None:
        raise HTTPException(status_code=401, detail="ログイン情報がありません。")
    username = r.get(session_id)
    if username is None:
        raise HTTPException(status_code=401, detail="ログイン情報がありません。")
    return {"username": username}

@router.get("/me-jwt")
def me_jwt(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if token is None:
        raise HTTPException(status_code=401, detail="ログイン情報がありません。")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="ログイン情報がありません。")
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="ログイン情報がありません")
    return {"username": username}

@router.get("/me-basic")
def me_basic(credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
    username = credentials.username
    password = credentials.password

    conn, cur = database.open_db()

    SELECT_HASHED_PASSWORD = """
        SELECT hashed_password FROM users WHERE username = %s;
    """
    try:
        cur.execute(SELECT_HASHED_PASSWORD, (username, ))
        result = cur.fetchone()
        if result is None:
            raise HTTPException(
                status_code=401,
                detail="ユーザーネームまたはパスワードが間違っています",
                headers={"WWW-Authenticate": "Basic"})
        is_valid = verify_password(password, result[0])
        if not is_valid:
            raise HTTPException(
                status_code=401,
                detail="ユーザーネームまたはパスワードが間違っています",
                headers={"WWW-Authenticate": "Basic"}
            )
    finally:
        database.close_db(conn, cur)
    return {"username": username}

@router.post("/logout")
def logout(response: Response, session_id: str = Cookie(default=None)):
    if session_id is not None:
        r.delete(session_id)
        response.delete_cookie(key="session_id")
    return {"message": "ログアウトしました"}

def verify_password(plain, hashed):
    """パスワード検証関数
    arg:
        plain: 平文パスワード
        hashed: ハッシュ化パスワード
    return:
        bool: パスワードが一致するかどうか
    """
    verify = bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
    return verify
