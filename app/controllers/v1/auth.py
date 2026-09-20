"""Auth REST endpoints — login, register, forgot-password, me."""

from fastapi import Cookie, Depends, Request, Response
from pydantic import BaseModel
from typing import Optional

from app.controllers.v1.base import new_router
from app.models.exception import HttpException
from app.services import auth as auth_service
from app.utils import utils

router = new_router()  # no verify_token dependency — auth is public


# ── request / response schemas ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    security_q1: str
    security_a1: str
    security_q2: str
    security_a2: str


class LoginRequest(BaseModel):
    username: str
    password: str


class ForgotPasswordStep1Request(BaseModel):
    username: str


class ForgotPasswordStep2Request(BaseModel):
    username: str
    answer1: str
    answer2: str
    new_password: str


class AuthResponse(BaseModel):
    status: int = 200
    message: str = "success"
    data: Optional[dict] = None


# ── endpoints ─────────────────────────────────────────────────────────────────

@router.get("/auth/questions", response_model=AuthResponse, summary="List security questions")
def list_questions():
    return {"status": 200, "message": "success", "data": {"questions": auth_service.SECURITY_QUESTIONS}}


@router.post("/auth/register", response_model=AuthResponse, summary="Register a new user")
def register(request: Request, body: RegisterRequest, response: Response):
    try:
        auth_service.register(
            username=body.username,
            email=body.email,
            password=body.password,
            security_q1=body.security_q1,
            security_a1=body.security_a1,
            security_q2=body.security_q2,
            security_a2=body.security_a2,
        )
        token = auth_service.login(body.username, body.password)
        response.set_cookie(
            key="session_token",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=60 * 60 * 24 * 7,
        )
        return {"status": 200, "message": "Registered successfully.", "data": {"username": body.username, "token": token}}
    except auth_service.AuthError as e:
        raise HttpException(task_id="register", status_code=400, message=str(e))


@router.post("/auth/login", response_model=AuthResponse, summary="Login")
def login(request: Request, body: LoginRequest, response: Response):
    try:
        token = auth_service.login(body.username, body.password)
        response.set_cookie(
            key="session_token",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=60 * 60 * 24 * 7,
        )
        return {"status": 200, "message": "Login successful.", "data": {"username": body.username, "token": token}}
    except auth_service.AuthError as e:
        raise HttpException(task_id="login", status_code=401, message=str(e))


@router.post("/auth/logout", response_model=AuthResponse, summary="Logout")
def logout(response: Response):
    response.delete_cookie("session_token")
    return {"status": 200, "message": "Logged out."}


@router.post("/auth/forgot-password/questions", response_model=AuthResponse, summary="Get security questions for user")
def forgot_password_questions(body: ForgotPasswordStep1Request):
    try:
        q1, q2 = auth_service.get_security_questions(body.username)
        return {"status": 200, "message": "success", "data": {"question1": q1, "question2": q2}}
    except auth_service.AuthError as e:
        raise HttpException(task_id="forgot", status_code=404, message=str(e))


@router.post("/auth/forgot-password/reset", response_model=AuthResponse, summary="Reset password using security answers")
def forgot_password_reset(body: ForgotPasswordStep2Request):
    try:
        auth_service.reset_password(
            username=body.username,
            answer1=body.answer1,
            answer2=body.answer2,
            new_password=body.new_password,
        )
        return {"status": 200, "message": "Password reset successfully."}
    except auth_service.AuthError as e:
        raise HttpException(task_id="reset", status_code=400, message=str(e))


@router.get("/auth/me", response_model=AuthResponse, summary="Get current user info")
def me(request: Request, session_token: Optional[str] = Cookie(default=None)):
    # also accept Bearer token
    token = session_token
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]

    if not token:
        raise HttpException(task_id="me", status_code=401, message="Not authenticated.")

    username = auth_service.verify_token(token)
    if not username:
        raise HttpException(task_id="me", status_code=401, message="Session expired or invalid.")

    try:
        info = auth_service.get_user_info(username)
        return {"status": 200, "message": "success", "data": info}
    except auth_service.AuthError as e:
        raise HttpException(task_id="me", status_code=404, message=str(e))
