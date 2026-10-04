"""Versões vulneráveis analisadas no Exercício 8. Montado apenas com CLINICA_MODO_DEMONSTRACAO_INSEGURA=true."""

from datetime import date, datetime
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Request, Security
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import text

from app import database
from app.auth import security
from app.auth.dependencies import Principal, SessaoDep, obter_principal
from app.auth.permissoes import AUDIENCIA_USUARIOS, escopos_do_papel
from app.db_models import Consulta
from app.limiter import limiter
from app.models import ConsultaPublic, PacientePublic, Token

router = APIRouter(prefix="/inseguro", tags=["demonstração vulnerável"])
templates = Jinja2Templates(directory="templates")

ROTAS_PUBLICAS_DEMONSTRACAO = frozenset({"/inseguro/auth/token", "/inseguro/web/agenda"})


@router.get("/consultas/{consulta_id}", response_model=ConsultaPublic)
def obter_consulta(
    consulta_id: int,
    sessao: SessaoDep,
    _: Annotated[Principal, Security(obter_principal, scopes=["consultas:ler"])],
):
    consulta = database.detalhar_consulta(sessao, consulta_id)
    if consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")
    return consulta


@router.get("/pacientes/busca")
def buscar_pacientes(
    nome: str,
    sessao: SessaoDep,
    _: Annotated[Principal, Security(obter_principal, scopes=["pacientes:ler"])],
):
    sql = f"SELECT id, nome, cpf, email FROM paciente WHERE nome LIKE '%{nome}%' ORDER BY nome"
    linhas = sessao.connection().execute(text(sql)).all()
    return [dict(linha._mapping) for linha in linhas]


@router.get("/pacientes/{paciente_id}", response_model=PacientePublic)
def obter_paciente(
    paciente_id: int,
    sessao: SessaoDep,
    _: Annotated[Principal, Security(obter_principal, scopes=["pacientes:ler"])],
):
    paciente = database.obter_paciente(sessao, paciente_id)
    if paciente is None:
        raise HTTPException(status_code=404, detail="Paciente não encontrado")
    return PacientePublic.de(paciente)


@router.post("/consultas", status_code=201)
def criar_consulta(
    corpo: dict,
    sessao: SessaoDep,
    principal: Annotated[Principal, Security(obter_principal, scopes=["consultas:escrever"])],
):
    dados = {
        "profissional_id": principal.usuario.profissional_id,
        "criado_por_id": principal.usuario.id,
        "token_auditoria": "aud_demo",
        **corpo,
    }
    dados["inicio"] = datetime.fromisoformat(dados["inicio"])
    consulta = Consulta.model_validate(dados)
    sessao.add(consulta)
    sessao.commit()
    sessao.refresh(consulta)
    return consulta.model_dump()


@router.get("/web/agenda", response_class=HTMLResponse)
def agenda(request: Request, sessao: SessaoDep, data: date | None = None):
    dia = data or date.today()
    return templates.TemplateResponse(
        request=request,
        name="agenda_inseguro.html",
        context={"consultas": database.listar_consultas(sessao, dia=dia), "dia": dia},
    )


@router.post("/auth/token", response_model=Token)
@limiter.exempt
def emitir_token(
    request: Request,
    sessao: SessaoDep,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
):
    usuario = database.obter_usuario_por_email(sessao, username)
    if usuario is None:
        raise HTTPException(status_code=401, detail="Usuário não cadastrado")
    if not security.verificar_senha(password, usuario.senha_hash):
        raise HTTPException(status_code=401, detail="Senha incorreta")
    escopos = escopos_do_papel(usuario.papel)
    token, expira = security.criar_token(
        sub=str(usuario.id), tipo="usuario", audiencia=AUDIENCIA_USUARIOS, escopos=escopos,
        expira_em_minutos=security.EXPIRACAO_USUARIO_MINUTOS, extras={"papel": usuario.papel, "mfa": False},
    )
    return Token(access_token=token, expires_in=expira, scope=" ".join(escopos))
