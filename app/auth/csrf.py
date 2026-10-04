import secrets

from fastapi import Request, Response

from app.config import configuracoes

COOKIE_CSRF = "csrf_clinica"
CAMPO_CSRF = "csrf_token"


def token_csrf(request: Request) -> str:
    return request.cookies.get(COOKIE_CSRF) or secrets.token_urlsafe(32)


def novo_token_csrf() -> str:
    return secrets.token_urlsafe(32)


def garantir_cookie_csrf(request: Request, resposta: Response, token: str) -> Response:
    if request.cookies.get(COOKIE_CSRF) == token:
        return resposta
    return gravar_cookie_csrf(resposta, token)


def gravar_cookie_csrf(resposta: Response, token: str) -> Response:
    resposta.set_cookie(
        COOKIE_CSRF,
        token,
        max_age=3600,
        path="/web",
        httponly=True,
        secure=configuracoes().cookie_seguro,
        samesite="strict",
    )
    return resposta


def csrf_valido(request: Request, enviado: str) -> bool:
    esperado = request.cookies.get(COOKIE_CSRF, "")
    if not esperado or not enviado:
        return False
    return secrets.compare_digest(esperado, enviado)
