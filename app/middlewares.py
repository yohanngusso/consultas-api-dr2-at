import re

import jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from app.auth.security import decodificar_token

COOKIE_SESSAO = "sessao_clinica"

ROTAS_PUBLICAS = frozenset({
    "/",
    "/auth/token",
    "/auth/mfa",
    "/web/login",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
    "/openapi.json",
})
PREFIXOS_PUBLICOS = ("/static/",)


def _token_da_requisicao(request: Request) -> str | None:
    cabecalho = request.headers.get("authorization", "")
    esquema, _, valor = cabecalho.partition(" ")
    if esquema.lower() == "bearer" and valor.strip():
        return valor.strip()
    if request.url.path.startswith("/web/"):
        return request.cookies.get(COOKIE_SESSAO)
    return None


class AutenticacaoJWTMiddleware(BaseHTTPMiddleware):
    """Único ponto que decodifica o JWT. Fail-closed: o que não está na allowlist pública exige token válido."""

    def __init__(self, app, rotas_publicas_extras: frozenset[str] = frozenset()):
        super().__init__(app)
        self.rotas_publicas = ROTAS_PUBLICAS | rotas_publicas_extras

    def _rota_publica(self, caminho: str) -> bool:
        return caminho in self.rotas_publicas or caminho.startswith(PREFIXOS_PUBLICOS)

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "OPTIONS" or self._rota_publica(request.url.path):
            return await call_next(request)

        token = _token_da_requisicao(request)
        if not token:
            return self._recusar(request, "Autenticação necessária")
        try:
            request.state.claims = decodificar_token(token)
        except jwt.ExpiredSignatureError:
            return self._recusar(request, "Token expirado")
        except jwt.InvalidTokenError:
            return self._recusar(request, "Token inválido")
        return await call_next(request)

    @staticmethod
    def _recusar(request: Request, detalhe: str) -> Response:
        if request.url.path.startswith("/web/"):
            resposta = RedirectResponse("/web/login", status_code=303)
            resposta.delete_cookie(COOKIE_SESSAO, path="/web")
            return resposta
        return JSONResponse(status_code=401, content={"detail": detalhe}, headers={"WWW-Authenticate": "Bearer"})


ROTAS_COM_POSSE: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GET", re.compile(r"^/consultas/(?!agenda$)[^/]+$")),
    ("PUT", re.compile(r"^/consultas/(?!agenda$)[^/]+$")),
    ("DELETE", re.compile(r"^/consultas/(?!agenda$)[^/]+$")),
    ("GET", re.compile(r"^/pacientes/(?!busca$)[^/]+$")),
)


class GuardaAutorizacaoMiddleware(BaseHTTPMiddleware):
    """Bloqueia resposta 2xx de rota com dado de titular específico que não passou por exigir_posse."""

    async def dispatch(self, request: Request, call_next) -> Response:
        resposta = await call_next(request)
        caminho = request.url.path
        sensivel = any(request.method == m and p.match(caminho) for m, p in ROTAS_COM_POSSE)
        if not sensivel or resposta.status_code >= 400 or getattr(request.state, "posse_verificada", False):
            return resposta
        return JSONResponse(
            status_code=500,
            content={"detail": "Rota sensível respondeu sem verificação de posse; resposta bloqueada."},
        )


CABECALHOS_DE_SEGURANCA = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

CSP_PADRAO = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
)

CSP_DOCUMENTACAO = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
)

ROTAS_DE_DOCUMENTACAO = ("/docs", "/redoc")
PREFIXO_DEMONSTRACAO = "/inseguro/"


class CabecalhosDeSegurancaMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        resposta = await call_next(request)
        caminho = request.url.path
        if caminho.startswith(PREFIXO_DEMONSTRACAO):
            return resposta

        for nome, valor in CABECALHOS_DE_SEGURANCA.items():
            resposta.headers.setdefault(nome, valor)

        if caminho in ROTAS_DE_DOCUMENTACAO:
            resposta.headers.setdefault("Content-Security-Policy", CSP_DOCUMENTACAO)
        else:
            resposta.headers.setdefault("Content-Security-Policy", CSP_PADRAO)
            resposta.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")

        if not caminho.startswith(PREFIXOS_PUBLICOS):
            resposta.headers.setdefault("Cache-Control", "no-store")
        return resposta
