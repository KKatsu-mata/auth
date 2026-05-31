import os
import redis
import uuid
from fastapi import APIRouter
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request
from starlette.config import Config
from dotenv import load_dotenv
from app.database import get_connection

load_dotenv()

router = APIRouter()
r = redis.Redis(host='localhost', port=6379, decode_responses=True)

config = Config(environ={
    "GOOGLE_CLIENT_ID": os.getenv("GOOGLE_CLIENT_ID"),
    "GOOGLE_CLIENT_SECRET": os.getenv("GOOGLE_CLIENT_SECRET"),
})

oauth = OAuth(config)
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

@router.get("/auth/google")
async def login_google(request: Request):
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/auth/callback")
async def auth_callback(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user_info = token.get("userinfo")

    # DB接続してgoogle_subでユーザ検索
    conn = get_connection()
    cur = conn.cursor()

    # ユーザが存在しなければ新規作成
    SEARCH_USER_SUB = """
        SELECT google_sub FROM users WHERE google_sub = %s;
    """
    cur.execute(SEARCH_USER_SUB, (user_info["sub"],))
    result = cur.fetchone()
    if result is None:
        CREATE_USER = """
            INSERT INTO users (google_sub) VALUES (%s);
        """
        cur.execute(CREATE_USER, (user_info["sub"], ))
        conn.commit()
        cur.close()
        conn.close()
    else:
        cur.close()
        conn.close()

    # セッションIDを発行してCookieで返す
    session_id = str(uuid.uuid4())
    r.setex(session_id, 1800, user_info["sub"])
    response = RedirectResponse(url="/docs")
    response.set_cookie(key="session_id", value=session_id)
    return response

