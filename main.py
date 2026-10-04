from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlmodel import Session

from app import database, seed
from app.config import configuracoes
from app.limiter import limiter, tratar_excesso_de_requisicoes
from app.middlewares import (
    AutenticacaoJWTMiddleware,
    CabecalhosDeSegurancaMiddleware,
    GuardaAutorizacaoMiddleware,
)
from app.routes import admin, auth, consultas, laboratorio, pacientes, profissionais, web

cfg = configuracoes()
VERSAO = "1.0.0"


@asynccontextmanager
async def ciclo_de_vida(app: FastAPI):
    database.criar_tabelas()
    if cfg.carregar_dados_demonstracao:
        with Session(database.engine) as sessao:
            seed.popular_dados_iniciais(sessao)
    yield


app = FastAPI(
    title="consultas-api",
    description="API de agendamento de consultas da rede de clínicas.",
    version=VERSAO,
    lifespan=ciclo_de_vida,
    docs_url="/docs" if cfg.docs_ativos else None,
    redoc_url="/redoc" if cfg.docs_ativos else None,
    openapi_url="/openapi.json" if cfg.docs_ativos else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, tratar_excesso_de_requisicoes)


@app.exception_handler(RequestValidationError)
async def erro_de_validacao(request: Request, exc: RequestValidationError) -> JSONResponse:
    erros = [{"type": e["type"], "loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": erros})


rotas_publicas_extras: frozenset[str] = frozenset()
if cfg.modo_demonstracao_insegura:
    from app.routes import inseguro

    rotas_publicas_extras = inseguro.ROTAS_PUBLICAS_DEMONSTRACAO
    app.include_router(inseguro.router)

app.add_middleware(GuardaAutorizacaoMiddleware)
app.add_middleware(AutenticacaoJWTMiddleware, rotas_publicas_extras=rotas_publicas_extras)
if cfg.rate_limit_ativo:
    app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.origens_permitidas,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)
app.add_middleware(CabecalhosDeSegurancaMiddleware)

app.include_router(auth.router)
app.include_router(consultas.router)
app.include_router(pacientes.router)
app.include_router(profissionais.router)
app.include_router(laboratorio.router)
app.include_router(admin.router)
app.include_router(web.router)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", tags=["status"])
def status_servico():
    return {"servico": "consultas-api", "status": "ok"}
