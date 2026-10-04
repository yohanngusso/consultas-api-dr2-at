from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app import database
from app.auth.dependencies import RESPOSTAS_DE_ERRO, Principal, SessaoDep, exigir_administrador
from app.models import RegistroAuditoriaPublic, UsuarioPublic

router = APIRouter(prefix="/admin", tags=["administração"], responses=RESPOSTAS_DE_ERRO)


@router.get("/usuarios", response_model=list[UsuarioPublic])
def listar_usuarios(sessao: SessaoDep, _: Annotated[Principal, Depends(exigir_administrador)]):
    return database.listar_usuarios(sessao)


@router.get("/auditoria", response_model=list[RegistroAuditoriaPublic])
def trilha_de_auditoria(
    sessao: SessaoDep,
    _: Annotated[Principal, Depends(exigir_administrador)],
    limite: Annotated[int, Query(ge=1, le=500)] = 100,
):
    return database.listar_auditoria(sessao, limite)
