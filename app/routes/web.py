from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Security, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import database
from app.auth import autenticacao
from app.auth.csrf import (
    CAMPO_CSRF,
    COOKIE_CSRF,
    csrf_valido,
    garantir_cookie_csrf,
    gravar_cookie_csrf,
    novo_token_csrf,
    token_csrf,
)
from app.auth.dependencies import Principal, SessaoDep, obter_principal
from app.auth.permissoes import escopos_do_papel
from app.auth.security import EXPIRACAO_USUARIO_MINUTOS
from app.config import configuracoes
from app.limiter import LIMITE_LOGIN, limiter
from app.middlewares import COOKIE_SESSAO
from app.models import ConsultaAgenda
from app.validators import data_na_janela

router = APIRouter(prefix="/web", tags=["páginas da recepção"], include_in_schema=False)
templates = Jinja2Templates(directory="templates")

CampoCSRF = Annotated[str, Form(alias=CAMPO_CSRF, max_length=64)]


def _pagina_login(request: Request, erro: str | None = None, status_code: int = 200) -> HTMLResponse:
    token = token_csrf(request)
    resposta = templates.TemplateResponse(
        request=request, name="login.html", context={"erro": erro, "csrf_token": token}, status_code=status_code
    )
    return garantir_cookie_csrf(request, resposta, token)


@router.get("/login", response_class=HTMLResponse)
def pagina_login(request: Request):
    return _pagina_login(request)


@router.post("/login", response_class=HTMLResponse)
@limiter.limit(LIMITE_LOGIN)
def entrar(
    request: Request,
    sessao: SessaoDep,
    email: Annotated[str, Form(max_length=180)],
    senha: Annotated[str, Form(max_length=128)],
    csrf: CampoCSRF = "",
):
    if not csrf_valido(request, csrf):
        return _pagina_login(request, "Formulário expirado. Tente novamente.", status.HTTP_403_FORBIDDEN)

    try:
        usuario = autenticacao.autenticar_usuario(sessao, request, email, senha)
    except HTTPException as erro:
        mensagem = "Muitas tentativas. Aguarde alguns minutos." if erro.status_code == 429 else "E-mail ou senha inválidos."
        return _pagina_login(request, mensagem, erro.status_code)

    if "agenda:ler" not in escopos_do_papel(usuario.papel) or usuario.mfa_obrigatorio:
        return _pagina_login(request, "A agenda é de uso exclusivo da recepção.", status.HTTP_403_FORBIDDEN)

    token = autenticacao.emitir_token_usuario(usuario, ["agenda:ler"], mfa=False)
    resposta = RedirectResponse("/web/agenda", status_code=status.HTTP_303_SEE_OTHER)
    resposta.set_cookie(
        COOKIE_SESSAO,
        token.access_token,
        max_age=EXPIRACAO_USUARIO_MINUTOS * 60,
        path="/web",
        httponly=True,
        secure=configuracoes().cookie_seguro,
        samesite="strict",
    )
    return gravar_cookie_csrf(resposta, novo_token_csrf())


@router.post("/logout")
def sair(request: Request, csrf: CampoCSRF = ""):
    if not csrf_valido(request, csrf):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token CSRF inválido")
    resposta = RedirectResponse("/web/login", status_code=status.HTTP_303_SEE_OTHER)
    resposta.delete_cookie(COOKIE_SESSAO, path="/web")
    resposta.delete_cookie(COOKIE_CSRF, path="/web")
    return resposta


@router.get("/agenda", response_class=HTMLResponse)
def pagina_agenda(
    request: Request,
    sessao: SessaoDep,
    principal: Annotated[Principal, Security(obter_principal, scopes=["agenda:ler"])],
    dia: Annotated[date, Depends(data_na_janela)],
):
    consultas = [ConsultaAgenda.model_validate(c) for c in database.listar_consultas(sessao, dia=dia)]
    token = token_csrf(request)
    resposta = templates.TemplateResponse(
        request=request,
        name="agenda.html",
        context={"consultas": consultas, "dia": dia, "usuario": principal.usuario.nome, "csrf_token": token},
    )
    return garantir_cookie_csrf(request, resposta, token)
