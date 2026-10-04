from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Security, status

from app import database
from app.auth.dependencies import RESPOSTAS_DE_ERRO, Principal, SessaoDep, auditar, obter_principal, paciente_legivel
from app.db_models import Paciente
from app.limiter import LIMITE_ESCRITA, LIMITE_LEITURA, limiter
from app.models import PacienteCreate, PacientePublic
from app.validators import termo_de_busca

router = APIRouter(prefix="/pacientes", tags=["pacientes"], responses=RESPOSTAS_DE_ERRO)


@router.get("/busca", response_model=list[PacientePublic])
@limiter.limit(LIMITE_LEITURA)
def buscar_pacientes(
    request: Request,
    sessao: SessaoDep,
    principal: Annotated[Principal, Security(obter_principal, scopes=["pacientes:ler"])],
    termo: Annotated[str, Depends(termo_de_busca)],
):
    restricao = principal.usuario.profissional_id if principal.papel == "profissional" else None
    pacientes = database.buscar_pacientes(sessao, termo, profissional_id=restricao)
    return [PacientePublic.de(p) for p in pacientes]


@router.get("/{paciente_id}", response_model=PacientePublic)
def obter_paciente(paciente_id: int, paciente: Annotated[Paciente, Depends(paciente_legivel)]):
    return PacientePublic.de(paciente)


@router.post("", response_model=PacientePublic, status_code=status.HTTP_201_CREATED)
@limiter.limit(LIMITE_ESCRITA)
def cadastrar_paciente(
    request: Request,
    dados: PacienteCreate,
    sessao: SessaoDep,
    principal: Annotated[Principal, Security(obter_principal, scopes=["pacientes:criar"])],
):
    if database.obter_profissional(sessao, dados.profissional_responsavel_id) is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Profissional responsável inexistente")
    if database.cpf_ja_cadastrado(sessao, dados.cpf):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Já existe paciente com este CPF")
    paciente = database.criar_paciente(sessao, dados)
    auditar(sessao, request, ator=principal.sub, tipo_ator=principal.tipo, acao="cadastrar_paciente",
            recurso="Paciente", recurso_id=paciente.id, resultado="sucesso")
    return PacientePublic.de(paciente)
