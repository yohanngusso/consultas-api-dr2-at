import logging

from fastapi import HTTPException, Request, status
from sqlmodel import Session

from app import database
from app.auth import security
from app.auth.dependencies import auditar
from app.auth.permissoes import (
    AUDIENCIA_LABORATORIO,
    AUDIENCIA_USUARIOS,
    escopos_do_papel,
    recortar_escopos,
)
from app.db_models import ClienteM2M, Usuario
from app.models import DesafioMFA, Token

log_mfa = logging.getLogger("consultas_api.mfa")


def _credenciais_invalidas(detalhe: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detalhe,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _conta_bloqueada() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Muitas tentativas inválidas para esta conta. Tente novamente mais tarde.",
        headers={"Retry-After": "900"},
    )


def autenticar_usuario(sessao: Session, request: Request, email: str, senha: str) -> Usuario:
    chave = f"usuario:{email.strip().lower()}"
    if security.identidade_bloqueada(chave):
        auditar(sessao, request, ator=email, tipo_ator="usuario", acao="login", recurso="sessao", resultado="bloqueado")
        raise _conta_bloqueada()

    usuario = database.obter_usuario_por_email(sessao, email)
    senha_ok = security.verificar_senha(senha, usuario.senha_hash if usuario else None)
    if usuario is None or not usuario.ativo or not senha_ok:
        security.registrar_falha_de_login(chave)
        auditar(sessao, request, ator=email, tipo_ator="usuario", acao="login", recurso="sessao", resultado="falha")
        raise _credenciais_invalidas("E-mail ou senha inválidos")

    security.limpar_falhas_de_login(chave)
    auditar(sessao, request, ator=str(usuario.id), tipo_ator="usuario", acao="login", recurso="sessao",
            resultado="sucesso")
    return usuario


def emitir_token_usuario(usuario: Usuario, escopos_pedidos: list[str], *, mfa: bool) -> Token:
    escopos = recortar_escopos(escopos_pedidos, escopos_do_papel(usuario.papel))
    token, expira_em = security.criar_token(
        sub=str(usuario.id),
        tipo="usuario",
        audiencia=AUDIENCIA_USUARIOS,
        escopos=escopos,
        expira_em_minutos=security.EXPIRACAO_USUARIO_MINUTOS,
        extras={"papel": usuario.papel, "amr": ["pwd", "otp"] if mfa else ["pwd"], "mfa": mfa},
    )
    return Token(access_token=token, expires_in=expira_em, scope=" ".join(escopos))


def iniciar_desafio_mfa(usuario: Usuario) -> DesafioMFA:
    challenge_id, codigo = security.gerar_desafio_mfa(usuario.id)
    log_mfa.warning("[MFA] desafio %s para %s: código %s", challenge_id, usuario.email, codigo)
    return DesafioMFA(
        challenge_id=challenge_id,
        detalhe="Conta administrativa exige segundo fator. Envie o código de 6 dígitos em POST /auth/mfa (válido por 5 minutos).",
    )


def autenticar_cliente(sessao: Session, request: Request, client_id: str, client_secret: str) -> ClienteM2M:
    chave = f"cliente:{client_id}"
    if security.identidade_bloqueada(chave):
        raise _conta_bloqueada()

    cliente = database.obter_cliente_m2m(sessao, client_id)
    segredo_ok = security.verificar_senha(client_secret, cliente.segredo_hash if cliente else None)
    if cliente is None or not cliente.ativo or not segredo_ok:
        security.registrar_falha_de_login(chave)
        auditar(sessao, request, ator=client_id, tipo_ator="servico", acao="login", recurso="sessao", resultado="falha")
        raise _credenciais_invalidas("client_id ou client_secret inválidos")

    security.limpar_falhas_de_login(chave)
    auditar(sessao, request, ator=client_id, tipo_ator="servico", acao="login", recurso="sessao", resultado="sucesso")
    return cliente


def emitir_token_cliente(cliente: ClienteM2M, escopos_pedidos: list[str]) -> Token:
    escopos = recortar_escopos(escopos_pedidos, cliente.escopos_contratados)
    if not escopos:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nenhum dos escopos solicitados está previsto no contrato deste cliente",
        )
    token, expira_em = security.criar_token(
        sub=cliente.client_id,
        tipo="servico",
        audiencia=AUDIENCIA_LABORATORIO,
        escopos=escopos,
        expira_em_minutos=security.EXPIRACAO_M2M_MINUTOS,
        extras={"cid": cliente.client_id, "parceiro": cliente.nome, "papel": "parceiro"},
    )
    return Token(access_token=token, expires_in=expira_em, scope=" ".join(escopos))
