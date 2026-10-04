from typing import Annotated

from fastapi import APIRouter, Security

from app import database
from app.auth.dependencies import RESPOSTAS_DE_ERRO, Principal, SessaoDep, obter_principal
from app.models import ProfissionalPublic

router = APIRouter(prefix="/profissionais", tags=["profissionais"], responses=RESPOSTAS_DE_ERRO)


@router.get("", response_model=list[ProfissionalPublic])
def listar_profissionais(
    sessao: SessaoDep,
    _: Annotated[Principal, Security(obter_principal, scopes=["profissionais:ler"])],
):
    return database.listar_profissionais(sessao)
