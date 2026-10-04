from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Security, status

from app import database
from app.auth.dependencies import (
    RESPOSTAS_DE_ERRO,
    Principal,
    SessaoDep,
    auditar,
    consulta_alteravel,
    consulta_legivel,
    exigir_profissional,
    ip_de,
    obter_principal,
    pode_ler_paciente,
)
from app.db_models import Consulta, Usuario
from app.limiter import LIMITE_ESCRITA, LIMITE_LEITURA, limiter
from app.models import ConsultaAgenda, ConsultaCreate, ConsultaPublic, ConsultaUpdate
from app.validators import data_na_janela

router = APIRouter(prefix="/consultas", tags=["consultas"], responses=RESPOSTAS_DE_ERRO)


@router.get("", response_model=list[ConsultaPublic])
@limiter.limit(LIMITE_LEITURA)
def listar_consultas(
    request: Request,
    sessao: SessaoDep,
    principal: Annotated[Principal, Security(obter_principal, scopes=["consultas:ler"])],
    data: date | None = None,
):
    filtro = {"dia": data}
    if principal.papel == "profissional":
        filtro["profissional_id"] = principal.usuario.profissional_id
    elif principal.papel == "paciente":
        filtro["paciente_id"] = principal.usuario.paciente_id
    elif not principal.e_administrador:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Papel sem acesso a consultas")
    return database.listar_consultas(sessao, **filtro)


@router.get("/agenda", response_model=list[ConsultaAgenda])
@limiter.limit(LIMITE_LEITURA)
def agenda_do_dia(
    request: Request,
    sessao: SessaoDep,
    _: Annotated[Principal, Security(obter_principal, scopes=["agenda:ler"])],
    dia: Annotated[date, Depends(data_na_janela)],
):
    return database.listar_consultas(sessao, dia=dia)


@router.post("", response_model=ConsultaPublic, status_code=status.HTTP_201_CREATED)
@limiter.limit(LIMITE_ESCRITA)
def criar_consulta(
    request: Request,
    dados: ConsultaCreate,
    sessao: SessaoDep,
    principal: Annotated[Principal, Security(obter_principal, scopes=["consultas:escrever"])],
    profissional: Annotated[Usuario, Depends(exigir_profissional)],
):
    paciente = database.obter_paciente(sessao, dados.paciente_id)
    if paciente is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Paciente não encontrado")
    if not pode_ler_paciente(principal, paciente):
        auditar(sessao, request, ator=principal.sub, tipo_ator="usuario", acao="criar_consulta",
                recurso="Paciente", recurso_id=paciente.id, resultado="negado")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Paciente não está sob sua responsabilidade")
    if database.existe_conflito(sessao, profissional.profissional_id, dados.inicio, dados.duracao_minutos):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Horário já ocupado na sua agenda")

    consulta = database.criar_consulta(
        sessao, dados, profissional_id=profissional.profissional_id, criado_por_id=profissional.id, ip=ip_de(request)
    )
    auditar(sessao, request, ator=principal.sub, tipo_ator="usuario", acao="criar_consulta",
            recurso="Consulta", recurso_id=consulta.id, resultado="sucesso")
    return database.detalhar_consulta(sessao, consulta.id)


@router.get("/{consulta_id}", response_model=ConsultaPublic)
def obter_consulta(
    consulta_id: int,
    sessao: SessaoDep,
    consulta: Annotated[Consulta, Depends(consulta_legivel)],
):
    return database.detalhar_consulta(sessao, consulta.id)


@router.put("/{consulta_id}", response_model=ConsultaPublic)
@limiter.limit(LIMITE_ESCRITA)
def atualizar_consulta(
    request: Request,
    consulta_id: int,
    dados: ConsultaUpdate,
    sessao: SessaoDep,
    consulta: Annotated[Consulta, Depends(consulta_alteravel)],
):
    if database.existe_conflito(sessao, consulta.profissional_id, dados.inicio, dados.duracao_minutos, consulta.id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Horário já ocupado na agenda")
    database.atualizar_consulta(sessao, consulta, dados, ip_de(request))
    return database.detalhar_consulta(sessao, consulta.id)


@router.delete("/{consulta_id}", response_model=ConsultaPublic)
@limiter.limit(LIMITE_ESCRITA)
def cancelar_consulta(
    request: Request,
    consulta_id: int,
    sessao: SessaoDep,
    consulta: Annotated[Consulta, Depends(consulta_alteravel)],
):
    database.cancelar_consulta(sessao, consulta, ip_de(request))
    return database.detalhar_consulta(sessao, consulta.id)
