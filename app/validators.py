import re
from datetime import date, datetime, timedelta, timezone
from typing import Annotated

from fastapi import HTTPException, Query, status

FUSO_CLINICA = timezone(timedelta(hours=-3))

PADRAO_TERMO_BUSCA = r"^[0-9A-Za-zÀ-ÖØ-öø-ÿ .\-]{2,60}$"
PADRAO_NOME_PESSOA = r"^[A-Za-zÀ-ÖØ-öø-ÿ' .\-]{3,120}$"
PADRAO_TELEFONE = r"^\(\d{2}\) \d{4,5}-\d{4}$"
PADRAO_TEXTO_LIVRE = r"^[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*$"

HORA_ABERTURA = 7
HORA_FECHAMENTO = 19
JANELA_MAXIMA_DIAS = 60

_regex_termo = re.compile(PADRAO_TERMO_BUSCA)


def agora_na_clinica() -> datetime:
    return datetime.now(FUSO_CLINICA).replace(tzinfo=None)


def cpf_e_valido(cpf: str) -> bool:
    digitos = [int(c) for c in cpf if c.isdigit()]
    if len(digitos) != 11 or len(set(digitos)) == 1:
        return False
    for posicao in (9, 10):
        soma = sum(digitos[i] * (posicao + 1 - i) for i in range(posicao))
        verificador = (soma * 10) % 11 % 10
        if verificador != digitos[posicao]:
            return False
    return True


def mascarar_cpf(cpf: str) -> str:
    digitos = "".join(c for c in cpf if c.isdigit())
    return f"***.{digitos[3:6]}.{digitos[6:9]}-**"


def validar_horario_de_atendimento(inicio: datetime) -> datetime:
    if inicio.tzinfo is not None:
        inicio = inicio.astimezone(FUSO_CLINICA).replace(tzinfo=None)
    if inicio < agora_na_clinica():
        raise ValueError("A consulta não pode começar no passado.")
    if inicio > agora_na_clinica() + timedelta(days=JANELA_MAXIMA_DIAS):
        raise ValueError(f"Agendamento limitado a {JANELA_MAXIMA_DIAS} dias à frente.")
    if not HORA_ABERTURA <= inicio.hour < HORA_FECHAMENTO:
        raise ValueError(f"Horário fora do expediente ({HORA_ABERTURA}h às {HORA_FECHAMENTO}h).")
    if inicio.minute % 15 or inicio.second or inicio.microsecond:
        raise ValueError("O início deve cair em intervalos de 15 minutos.")
    return inicio


def termo_de_busca_e_valido(termo: str) -> bool:
    return bool(_regex_termo.fullmatch(termo))


def normalizar_termo(termo: str) -> str:
    return re.sub(r"\s+", " ", termo).strip()


def termo_de_busca(
    nome: Annotated[
        str,
        Query(
            min_length=2,
            max_length=60,
            description="Parte do nome do paciente. Aceita letras, dígitos, espaço, ponto e hífen.",
        ),
    ],
) -> str:
    termo = normalizar_termo(nome)
    if not termo_de_busca_e_valido(termo):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Termo de busca inválido: use apenas letras, dígitos, espaço, ponto e hífen (2 a 60 caracteres).",
        )
    return termo


def data_na_janela(
    data: Annotated[date | None, Query(description="Dia consultado (AAAA-MM-DD). Padrão: hoje.")] = None,
) -> date:
    hoje = agora_na_clinica().date()
    alvo = data or hoje
    if not hoje - timedelta(days=JANELA_MAXIMA_DIAS) <= alvo <= hoje + timedelta(days=JANELA_MAXIMA_DIAS):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Data fora da janela de {JANELA_MAXIMA_DIAS} dias.",
        )
    return alvo
