from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status

from app import database
from app.auth import autenticacao
from app.auth.dependencies import RESPOSTAS_DE_ERRO, Principal, SessaoDep, obter_principal
from app.auth.security import validar_desafio_mfa
from app.limiter import LIMITE_LOGIN, limiter
from app.models import DesafioMFA, Token, VerificacaoMFA

router = APIRouter(prefix="/auth", tags=["autenticação"])


class PedidoDeToken:
    def __init__(
        self,
        grant_type: Annotated[str, Form(pattern=r"^(password|client_credentials)$")] = "password",
        username: Annotated[str, Form(max_length=180)] = "",
        password: Annotated[str, Form(max_length=128)] = "",
        scope: Annotated[str, Form(max_length=300, pattern=r"^[a-z: ]*$")] = "",
        client_id: Annotated[str, Form(max_length=60)] = "",
        client_secret: Annotated[str, Form(max_length=128)] = "",
    ):
        self.grant_type = grant_type
        self.username = username
        self.password = password
        self.escopos = scope.split()
        self.client_id = client_id
        self.client_secret = client_secret


@router.post("/token", response_model=Token | DesafioMFA, summary="Emite access token (password ou client_credentials)")
@limiter.limit(LIMITE_LOGIN)
def emitir_token(request: Request, sessao: SessaoDep, form: Annotated[PedidoDeToken, Depends()]):
    if form.grant_type == "client_credentials":
        cliente = autenticacao.autenticar_cliente(sessao, request, form.client_id, form.client_secret)
        return autenticacao.emitir_token_cliente(cliente, form.escopos)

    usuario = autenticacao.autenticar_usuario(sessao, request, form.username, form.password)
    if usuario.mfa_obrigatorio:
        return autenticacao.iniciar_desafio_mfa(usuario)
    return autenticacao.emitir_token_usuario(usuario, form.escopos, mfa=False)


@router.post("/mfa", response_model=Token, summary="Conclui o login administrativo com o segundo fator")
@limiter.limit(LIMITE_LOGIN)
def verificar_mfa(request: Request, sessao: SessaoDep, dados: VerificacaoMFA):
    usuario_id = validar_desafio_mfa(dados.challenge_id, dados.codigo)
    usuario = database.obter_usuario_por_id(sessao, usuario_id) if usuario_id else None
    if usuario is None or not usuario.ativo:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Desafio de MFA inválido, expirado ou já utilizado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return autenticacao.emitir_token_usuario(usuario, [], mfa=True)


@router.get("/eu", summary="Claims do token apresentado", responses=RESPOSTAS_DE_ERRO)
def quem_sou_eu(principal: Annotated[Principal, Depends(obter_principal)]) -> dict:
    return {"tipo": principal.tipo, "papel": principal.papel, "escopos": principal.escopos, "claims": principal.claims}
