from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import configuracoes

_cfg = configuracoes()

LIMITE_PADRAO = _cfg.rate_limit_padrao
LIMITE_LOGIN = _cfg.rate_limit_login
LIMITE_ESCRITA = _cfg.rate_limit_escrita
LIMITE_LEITURA = _cfg.rate_limit_leitura

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[LIMITE_PADRAO],
    enabled=_cfg.rate_limit_ativo,
    storage_uri="memory://",
)


def tratar_excesso_de_requisicoes(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": "Muitas requisições. Aguarde antes de tentar novamente."},
        headers={"Retry-After": "60"},
    )


def resetar_limites() -> None:
    limiter.reset()
