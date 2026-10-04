from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from app import database
from app.auth.dependencies import RESPOSTAS_DE_ERRO, Principal, SessaoDep, exigir_laboratorio
from app.limiter import LIMITE_LEITURA, limiter
from app.models import Especialidade, HorarioDisponivel
from app.validators import data_na_janela

router = APIRouter(prefix="/laboratorio", tags=["integração laboratório"], responses=RESPOSTAS_DE_ERRO)


@router.get("/horarios-disponiveis", response_model=list[HorarioDisponivel])
@limiter.limit(LIMITE_LEITURA)
def horarios_disponiveis(
    request: Request,
    sessao: SessaoDep,
    _: Annotated[Principal, Depends(exigir_laboratorio)],
    dia: Annotated[date, Depends(data_na_janela)],
    especialidade: Annotated[Especialidade, Query()],
):
    return database.horarios_disponiveis(sessao, dia, especialidade.value)
