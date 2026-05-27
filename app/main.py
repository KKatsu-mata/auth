from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from app.routers import auth, oauth

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="your-secret-key")
app.include_router(auth.router)
app.include_router(oauth.router)
