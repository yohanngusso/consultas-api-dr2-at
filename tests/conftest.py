import os
import pathlib
import re
import tempfile
from datetime import datetime, time, timedelta

BANCO_DE_TESTE = pathlib.Path(tempfile.gettempdir()) / "consultas_api_testes.db"
os.environ["CLINICA_DATABASE_URL"] = f"sqlite:///{BANCO_DE_TESTE.as_posix()}"
os.environ["CLINICA_JWT_SECRET"] = "segredo-exclusivo-da-suite-de-testes-0123456789"
os.environ["CLINICA_CORS_ORIGENS"] = "http://localhost:5173"
os.environ["CLINICA_COOKIE_SEGURO"] = "false"
os.environ["CLINICA_RATE_LIMIT_ATIVO"] = "true"
os.environ["CLINICA_MODO_DEMONSTRACAO_INSEGURA"] = "false"
os.environ["CLINICA_CARREGAR_DADOS_DEMONSTRACAO"] = "true"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel  # noqa: E402

import main  # noqa: E402
from app import database, seed  # noqa: E402
from app.auth import security  # noqa: E402
from app.limiter import resetar_limites  # noqa: E402
from app.validators import agora_na_clinica  # noqa: E402

ADMIN = ("admin@clinica.dev", "SenhaAdmin#2026")
RECEPCAO = ("recepcao@clinica.dev", "SenhaRecepcao#2026")
HELENA = ("helena@clinica.dev", "SenhaHelena#2026")
MARCOS = ("marcos@clinica.dev", "SenhaMarcos#2026")
JOAO = ("joao@paciente.dev", "SenhaJoao#2026")
MARIA = ("maria@paciente.dev", "SenhaMaria#2026")
LABORATORIO = ("laboratorio-parceiro", "e784ad17f9385f8f221db15796c5bff8")


def amanha_as(hora: int, minuto: int = 0) -> str:
    dia = agora_na_clinica().date() + timedelta(days=1)
    return datetime.combine(dia, time(hora, minuto)).isoformat()


@pytest.fixture(autouse=True)
def banco_limpo():
    SQLModel.metadata.drop_all(database.engine)
    SQLModel.metadata.create_all(database.engine)
    with Session(database.engine) as sessao:
        seed.popular_dados_iniciais(sessao)
    resetar_limites()
    security.resetar_estado_em_memoria()
    yield


@pytest.fixture
def cliente():
    with TestClient(main.app) as c:
        yield c


def _token_de_usuario(cliente: TestClient, credenciais: tuple[str, str], escopo: str = "") -> str:
    email, senha = credenciais
    resposta = cliente.post("/auth/token", data={"username": email, "password": senha, "scope": escopo})
    assert resposta.status_code == 200, resposta.text
    return resposta.json()["access_token"]


def _token_de_admin(cliente: TestClient) -> str:
    email, senha = ADMIN
    desafio = cliente.post("/auth/token", data={"username": email, "password": senha}).json()
    codigo = security._desafios_mfa[desafio["challenge_id"]]["codigo"]
    resposta = cliente.post("/auth/mfa", json={"challenge_id": desafio["challenge_id"], "codigo": codigo})
    assert resposta.status_code == 200, resposta.text
    return resposta.json()["access_token"]


def _token_do_laboratorio(cliente: TestClient, escopo: str = "horarios:ler") -> str:
    client_id, segredo = LABORATORIO
    resposta = cliente.post(
        "/auth/token",
        data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": segredo, "scope": escopo},
    )
    assert resposta.status_code == 200, resposta.text
    return resposta.json()["access_token"]


def entrar_na_recepcao(cliente: TestClient, credenciais: tuple[str, str]):
    pagina = cliente.get("/web/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', pagina.text).group(1)
    email, senha = credenciais
    return cliente.post("/web/login", data={"email": email, "senha": senha, "csrf_token": csrf}, follow_redirects=False)


@pytest.fixture
def autenticar(cliente):
    """Devolve cabeçalhos Authorization para 'admin', 'laboratorio' ou uma tupla de credenciais."""

    def _autenticar(quem, escopo: str = "") -> dict:
        if quem == "admin":
            token = _token_de_admin(cliente)
        elif quem == "laboratorio":
            token = _token_do_laboratorio(cliente, escopo or "horarios:ler")
        else:
            token = _token_de_usuario(cliente, quem, escopo)
        return {"Authorization": f"Bearer {token}"}

    return _autenticar
